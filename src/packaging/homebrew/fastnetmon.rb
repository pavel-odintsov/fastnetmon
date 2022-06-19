class Fastnetmon < Formula
  desc "DDoS detection tool with sFlow, Netflow, IPFIX and port mirror support"
  homepage "https://github.com/pavel-odintsov/fastnetmon/"
  url "https://github.com/pavel-odintsov/fastnetmon/archive/78baf3be83bb56e03528a96fe6df37eb20876cd9.tar.gz"
  version "1.2.2"
  sha256 "ed9376fc193cbd2dd36eb5e80a2d03143f2ab0b6b4d9d74ae3572cc544754b20"
  license "GPL-2.0-only"

  depends_on "cmake" => :build
  depends_on "abseil"
  depends_on "boost"
  depends_on "capnp"
  depends_on "grpc"
  depends_on "hiredis"
  depends_on "json-c"
  depends_on "log4cpp"
  depends_on macos: :big_sur # We need C++ 20 available for build which is available from Big Sur
  depends_on "mongo-c-driver"
  depends_on "openssl@1.1"

  on_linux do
    depends_on "gcc"
    depends_on "libpcap"
    depends_on "ncurses"
  end

  fails_with gcc: "5"

  def install
    system "cmake", "-S", "src", "-B", "build",
      "-DENABLE_CUSTOM_BOOST_BUILD=FALSE",
      "-DDO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD=FALSE",
      "-DLINK_WITH_ABSL=TRUE",
      "-DSET_ABSOLUTE_INSTALL_PATH=OFF",
      "-DCMAKE_SYSTEM_INCLUDE_PATH=#{Formula["openssl@1.1"].include}",
      "-DCMAKE_SYSTEM_LIBRARY_PATH=#{Formula["openssl@1.1"].lib}", *std_cmake_args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  service do
    run [
      opt_sbin/"fastnetmon",
      "--configuration_file",
      etc/"fastnetmon.conf",
      "--log_to_console",
      "--disable_pid_logic",
    ]
    keep_alive false
    working_dir HOMEBREW_PREFIX
  end

  test do
    cp etc/"fastnetmon.conf", testpath

    inreplace testpath/"fastnetmon.conf", "/tmp/fastnetmon.dat", testpath/"fastnetmon.dat"

    inreplace testpath/"fastnetmon.conf", "/tmp/fastnetmon_ipv6.dat", testpath/"fastnetmon_ipv6.dat"

    fastnetmon_pid = fork do
      exec opt_sbin/"fastnetmon",
      "--configuration_file",
      testpath/"fastnetmon.conf",
      "--log_to_console",
      "--disable_pid_logic"
    end

    sleep 15

    assert_path_exists testpath/"fastnetmon.dat"

    ipv4_stats_output = File.read(testpath/"fastnetmon.dat")
    assert_match("Incoming traffic", ipv4_stats_output)

    assert_path_exists testpath/"fastnetmon_ipv6.dat"

    ipv6_stats_output = File.read(testpath/"fastnetmon_ipv6.dat")
    assert_match("Incoming traffic", ipv6_stats_output)
  ensure
    Process.kill "SIGTERM", fastnetmon_pid
  end
end
