class Fastnetmon < Formula
  desc "DDoS detection tool with sFlow, Netflow, IPFIX and port mirror support"
  homepage "https://github.com/pavel-odintsov/fastnetmon/"
  url "https://github.com/pavel-odintsov/fastnetmon/archive/9ec38c73ee4a4ff7af1f29d07af2a1e58e513af0.tar.gz"
  version "1.2.2"
  sha256 "2451c4b65579a8e991dcb88a1e2ad6556ab01b23a79867d871b5e0148530b419"
  license "GPL-2.0-only"
  revision 1

  depends_on "cmake" => :build
  depends_on "boost"
  depends_on "log4cpp"
  depends_on "hiredis"
  depends_on "json-c"
  depends_on "mongo-c-driver"
  depends_on "grpc"
  depends_on "capnp"
  depends_on "openssl@3"

  def install
    system "cmake", "-S", "src", "-B", "build", "-DENABLE_CUSTOM_BOOST_BUILD=FALSE", "-DDO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD=FALSE", "-DCMAKE_SYSTEM_INCLUDE_PATH=/usr/local/opt/openssl\@3/include", "-DCMAKE_SYSTEM_LIBRARY_PATH=/usr/local/opt/openssl\@3/lib", *std_cmake_args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

 service do
    run [opt_bin/"fastnetmon", "--config", etc/"fastnetmon.conf", "--log_to_console", "--disable_pid_logic"]
    keep_alive false
    working_dir HOMEBREW_PREFIX
  end
end

