#!/usr/bin/perl

###
### This tool builds all binary dependencies required for FastNetMon
###


use strict;
use warnings;

use FindBin;

use lib "$FindBin::Bin/perllib";

use Fastnetmon;
use Getopt::Long;

#
# CentOS
# sudo yum install perl perl-Archive-Tar
#

my $library_install_folder = '/opt/fastnetmon-community/libraries';

my $os_type = '';  
my $distro_type = '';  
my $distro_version = '';  
my $distro_architecture = '';  
my $appliance_name = ''; 

my $temp_folder_for_building_project = `mktemp -d /tmp/fastnetmon.build.dir.XXXXXXXXXX`;
chomp $temp_folder_for_building_project;

unless ($temp_folder_for_building_project && -e $temp_folder_for_building_project) {
    die "Can't create temp folder in /tmp for building project: $temp_folder_for_building_project\n";
}

# Pass log path to module
$Fastnetmon::install_log_path = '/tmp/fastnetmon_install.log';

# We do not need default very safe permissions
exec_command("chmod 755 $temp_folder_for_building_project");

my $start_time = time();

my $fastnetmon_code_dir = "$temp_folder_for_building_project/fastnetmon/src";

my $cpus_number = 1;

# We could pass options to make with this variable
my $make_options = '';

unless (-e $library_install_folder) {
    exec_command("mkdir -p $library_install_folder");
}

main();

### Functions start here
sub main {
    my $machine_information = Fastnetmon::detect_distribution();

    unless ($machine_information) {
        die "Could not collect machine information\n";
    }

    $distro_version = $machine_information->{distro_version};
    $distro_type = $machine_information->{distro_type};
    $os_type = $machine_information->{os_type};
    $distro_architecture = $machine_information->{distro_architecture};
    $appliance_name = $machine_information->{appliance_name};
	
    $Fastnetmon::library_install_folder = $library_install_folder;
    $Fastnetmon::temp_folder_for_building_project = $temp_folder_for_building_project;

    $cpus_number = Fastnetmon::get_logical_cpus_number();

    print "Your machine has $cpus_number CPUs\n";

    # We could get huge speed benefits with this option
    if ($cpus_number > 1) { 
        print "You have really nice server with $cpus_number CPU's and we will use they all for build process :)\n";
        $make_options = "-j $cpus_number";
    }

    # Install build dependencies
    my $dependencies_install_start_time = time();
    install_build_dependencies();

    print "Installed dependencies in ", time() - $dependencies_install_start_time, " seconds\n";

    # Init environment
    init_compiler();

    # We do not use prefix "lib" in names as all of them are libs and it's meaning less
    # We use target folder names in this list for clarity
    # Versions may be in different formats and we do not use them yet
    my @required_packages = (
        # 'gcc', # we build it separately as it requires excessive amount of time
        'openssl_1_1_1q',
        'cmake_3_23_4',
        
        'boost_build_4_9_2',
        'icu_65_1',
        'boost_1_81_0',

        'capnproto_0_8_0',
        'hiredis_0_14',
        'mongo_c_driver_1_23_0',
        
        # gRPC dependencies 
        're2_2022_12_01',
        'abseil_2022_06_23',        
        'zlib_1_2_13',,
        'cares_1_18_1',

        'protobuf_21_12',
        'grpc_1_49_2',
        
        'elfutils_0_186',
        'bpf_1_0_1',
        
        'gobgp_2_27_0',
        'log4cpp_1_1_3',
    );

    # Accept package name from command line argument
    if (scalar @ARGV > 0) {
        @required_packages = @ARGV;
    }

    # To guarantee that binary dependencies are not altered in storage side we store their hashes in repository
    my $binary_build_hashes = { 
        'gcc_12_1_0' => {
            'debian:9'            => '63995539b8fb75cc89cc7eb3a2b78aaf55a5083fb95bb2b5199b2f4545329789410c54f04f7449a2f96543f21d51977bdd2b9ede10c70f910459dae83b030212',
            'debian:10'           => '2c18964400a6660eae4ee36369c50829fda4ad4ee049c29aa1fd925bf96c3f8eed3ecb619cc02c6f470d0170d56aee1c840a4ca58d8132ca7ae395759aa49fc7',
            'debian:11'           => '3ad28bf950a7be070f1de9b3184f1fe9f42405cdbc0f980ab97e13d571a5be1441963a43304d784c135a43278454149039bd2a6252035c7755d4ba5e0eb41480',
            'debian:bookworm/sid' => '907bf0bb451c5575105695a98c3b9c61ff67ad607bcd6a133342dfddd80d8eac69c7af9f97d215a7d4469d4885e5d6914766c77db8def4efa92637ab2c12a515',
            
            'ubuntu:16.04'        => '433789f72e40cb8358ea564f322d6e6c117f6728e5e1f16310624ee2606a1d662dad750c90ac60404916aaad1bbf585968099fffca178d716007454e05c49237',
            'ubuntu:18.04'        => '7955ab75d491bd19002e0e6d540d7821f293c2f8acb06fdf2cb5778cdae8967c636a2b253ee01416ea1cb30dc11d363d4a91fb59999bf3fc8f2d0030feaaba4e',
            
            'centos:7'            => 'f7bb6b23d338fa80e1a72912d001ef926cbeb1df26f53d4c75d5e20ffe107e146637cb583edd08d02d252fc1bb93b2af6b827bd953713a9f55de148fb10b55aa',
        },
        'openssl_1_1_1q'        => {
            'centos:7'            => 'ab9dde43afc7b6bcc4399b6fbd746727e0ce72cf254e9b7f6abcc5c22b319ab82c051546decc6804e508654975089888c544258514e30dc18385ad1dd59d63fb',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'd284915be431493b4c336d452478a28906a8268c4079fbb19c8851cf70a1a9eefe942a424e922caa4bc38eaf66b40a9971576a62ba0aebe7fd20d05b2bdeacf0',
            'debian:10'           => 'eac2b5a066386f7900b1e364b5347d87ab4a994a058ecfaf5682a9325fc72362b8532ddf974e092c08bebd9f4cc4b433e00c3ab564c532fa6ed1f30a6b354626',
            'debian:11'           => 'd1b1aeecbfb848a0f58316e46b380a9c15773646fe79b3d8dca81cb9ef2dce84ee15375a19df6b1146ca19e05b38d42512aed1c35a8d26e9db0ebe0733acdff9',
            'debian:bookworm/sid' => '793055b1e9cb0eb63b3e00d9e31a0f10447ffdf4166e642cc82b4fd78fd658a2c315db3911eec22fae57e5f859230fe557bb541462ae0af8e5d158295342762f',

            'ubuntu:16.04'        => 'e5af3f4008f715319cc2ca69e6b3d5f720322887de5f7758e4cbd7090e5282bb172d1e4b26ef88ca9a5212efd852658034ddac51ea86c4ca166c86e46e7d5809',
            'ubuntu:18.04'        => 'ec1dbceef7c3db5aca772f0ec313a9220ead22347957e8c24951b536477093d6561c3b6b2c9d1b876b30b52f793b5b3ab7dc8c4c9b6518f56d144e88cb4508e9',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        }, 
        'cmake_3_23_4'          => {
            'centos:7'            => 'f19d35583461af4a8e90a2c6d3751c586eaae3d18dcf849f992af9add78cf190afe2c5e010ddb9f5913634539222ceb218c2c04861b71691c38f231b3f49f6c5',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'd23bc4b5e5b8ab39ecb2046629a259265ea82f9247785c4c63cef2c11f0eb8064476f3d775a5b94ce0272f9a3227f2b618d87dae387840b69e468b9985416398',
            'debian:10'           => 'cab3412debee6f864551e94f322d453daca292e092eb67a5b7f1cd0025d1997cfa60302dccc52f96be09127aee493ab446004c1e578e1725b4205f8812abd9ea',
            'debian:11'           => '9aac32d98835c485d9a7a82fd4269b8c5178695dd0ba28ed338212ca6c45a26bff9a0c511c111a45c286733d5cdf387bcc3fb1d00340c179db6676571e173656',
            'debian:bookworm/sid' => '9f08c5776349b9491821669d3e480c5bbd072410f4b8419c0d12ffbf52b254bddb96ee6e89f02e547efcf6f811025dbbbc476e2506f3a30c34730d72ad1de656',

            'ubuntu:16.04'        => '156c5de5de7daae35723934eb61396e257fab4d08224d19af9e0d076324052ce14f1c7e69bae07d595686430b6b197ec5b911944d4410e0456d4465888200870',
            'ubuntu:18.04'        => '1d0c06bea58cba2d03dbc4c9b17e12c07d5c41168473dee34bfcd7ab21169ab1082d9024458a62247ae7585cf98c86d8e64508c3eab9d9653dee1357481fc866',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'boost_build_4_9_2'     => {
            'centos:7'            => 'd395a8e369d06e8c8ef231d2ffdaa9cacbc0da9dc3520d71cd413c343533af608370c7b9a93843facbd6d179270aabebc9dc4a56f0c1dea3fe4e2ffb503d7efd',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => '6d61189b93fe0c115923ee070ff66f0539e1d93a14d0f7880578ffde9b26bfa13cbaa080deca9870285533a5fcbad14b4d17a3a6f6cb234a097e635b7aaa259f',
            'debian:10'           => '89c1a916456f85aa76578d5d85b2c0665155e3b7913fd79f2bb6309642dab54335b6febcf6395b2ab4312c8cc5b3480541d1da54137e83619f825a1be3be2e4e',
            'debian:11'           => 'f434ddf167a36c5ec5f4dd87c9913fb7463427e4cda212b319d245a8df7c0cb41ec0a7fb399292a7312af1c118de821cf0d87ac9dcd00eed2ea06f59e3415da2', 
            'debian:bookworm/sid' => '283835e4cb70db05f205280334614391d932bea4dc71916192e80f7625b51aade7b939f4a683c310f49d7fbcd815318b261d8d34668bb3cc205015448dc973b3',

            'ubuntu:16.04'        => '0361e191dc9010bbe725eaccea802adad2fced77c4d0152fc224c3fd8dfc474dd537945830255d375796d8153ecfb985d6ee16b5c88370c24dbd28a5f71a8f56',
            'ubuntu:18.04'        => 'bc4287b1431776ae9d2c2c861451631a6744d7ae445630e96a2bb2d85a785935e261735c33a4a79a4874e6f00a7dd94252bc5e88ddce85b41f27fba038fea5a2',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'icu_65_1'              => {
            'centos:7'            => '4360152b0d4c21e2347d6262610092614b671da94592216bd7d3805ab5dbeae7159a30af5ab3e8a63243ff66d283ad4c7787b29cf5d5a7e00c4bad1a040b19a2',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'bdf9c89926d3aff1c5b65d20b94b2bddece53841732349bcb15f956025f950809e0212841712f21b52c5286c513066c01fa025a0e06ab9feee9bef8f7b74372d',
            'debian:10'           => '1c10db8094967024d5aec07231fb79c8364cff4c850e0f29f511ddaa5cfdf4d18217bda13c41a1194bd2b674003d375d4df3ef76c83f6cbdf3bea74b48bcdcea',
            'debian:11'           => '0cca0308c2f400c7998b1b2fce391ddef4e77eead15860871874b2513fe3d7da544fdceca9bcbee9158f2f6bd1f786e0aa3685a974694b2c0400a3a7adba31c8', 
            'debian:bookworm/sid' => 'de03047ca1326fa45f738a1a0f85e6e587f2a92d7badfaff494877f6d9ca38276f0b18441ebe752ac65f522e48f8c26cd0cfa382dd3daac36e7ea7a027a4a367',

            'ubuntu:16.04'        => '4038a62347794808f7608f0e4ee15841989cf1b33cab443ea5a29a20f348d179d96d846931e8610b823bde68974e75e95be1f46e71376f84af79d7c84badeea4',
            'ubuntu:18.04'        => '549423e7db477b4562d44bbd665e0fb865a1b085a8127746b8dbbaa34571a193aaa4a988dac68f4cd274b759200441b3d2a07ae2c99531d548775a915b79bb61',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'boost_1_81_0'          => {
            'centos:7'            => '',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => '',
            'debian:10'           => '',
            'debian:11'           => '',
            'debian:bookworm/sid' => '',

            'ubuntu:16.04'        => '',
            'ubuntu:18.04'        => '',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'capnproto_0_8_0'       => {
            'centos:7'            => '5c796240cb57179122653b61ee3ef45ca3d209ad83695424952be93bb3aad89e6e660dba034df94d55cc38d3251c438a2eb81b7de2ed9db967154d72441b2e12',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => '7c6b3c073ab6461daef783ab08d367df56730764bc43d1c2a66d6a4001744400a98adf0399326ceb303f2d609c206858c311300eb06b252bf899d5a5616f142e',
            'debian:10'           => 'e9ba7567657d87d908ff0d00a819ad5da86476453dc207cf8882f8d18cbc4353d18f90e7e4bcfbb3392e4bc2007964ea0d9efb529b285e7f008c16063cce4c4e',
            'debian:11'           => '72c91ed5df207aa9e86247d7693cda04c0441802acd4bf152008c5e97d7e9932574d5c96a9027a77af8a59c355acadb0f091d39c486ea2a37235ea926045e306', 
            'debian:bookworm/sid' => 'aeeff7188c350252c9d1364c03c8838c55665fd9b7dd5ebea1832f4f9712196027bfa0a424f88e82449f1de1b5c4864eb28877d2746f3047001803974bd1e916',

            'ubuntu:16.04'        => '5709dc2477169cec3157a7393a170028a61afdfab194d5428db5e8800e4f02bd8b978692ae75dae9642adca4561c66733f3f0c4c19ec85c8081cc2a818fed913',
            'ubuntu:18.04'        => '3c1281ed39b7d5b8facdb8282e3302f5871593b1c7c63be8c9eb79c0d1c95a8636faa52ce75b7a8f99c2f8f272a21c8fc0c99948bbf8d973cb359c5ae26bb435',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'hiredis_0_14'          => {
            'centos:7'            => '03afc34178805b87ef5559ead86c70b5ae315dd407fe7627d6d283f46cf94fd7c41b38c75099703531ae5a08f08ec79a349feef905654de265a7f56b16a129f1',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'dae76b5ff1749f9b28af8b2bb87e36879312bad7f6ea1f622e87f957eb1d8c9ea7eb4591a92a175f7db58268371a6c70de7d07cbffa43e763c326a08bbf09cb9',
            'debian:10'           => '76ca19f7cd4ec5e0251bc4804901acbd6b70cf25098831d1e16da85ad18d4bb2a07faa1a8e84e1d58257d5b8b1d521b5e49135ce502bd16929c0015a00f4089d',
            'debian:11'           => 'c0effe2b28aa9c63c0d612c6a2961992b8d775c80cb504fdbb892eb20de24f3cb89eb159c46488ae3f01c254703f2bb504794b2b6582ce3adfb7875a3cb9c01c', 
            'debian:bookworm/sid' => '0fd3ccfecff6eea982931f862bdfa67faf909e49188173a8184a5f38a15c592536316a202a1aada164a90d9f34eca991fee681d3a41b76a0c14c9eb830e60db4',

            'ubuntu:16.04'        => '268de5b8e759752333f2b8c79185fdb7059e6510bc2d8bf10fe75a37db92ba833a95ddd09b0b50e237de5812aa2c1f336fa6f4cc67da5f60d9aa4a862b2afdfd',
            'ubuntu:18.04'        => '5171604d9e0f019c22e8b871dd247663d1c2631a2aa5b7706bf50e9f62f6b1cef82db2fe3d0ff0248493c175fb83d0434339d7d8446c587947ab187fabf5fff4',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'mongo_c_driver_1_23_0' => {
            'centos:7'            => '8ea15364969ad3e31b3a94ac41142bb3054a7be2809134aa4d018ce627adf9d2c2edd05095a8ea8b60026377937d74eea0bfbb5526fccdcc718fc4ed8f18d826',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => '5b41952d68747fbe4d402b2f5be29250e68936599fc0254cc79c4518548b209056a24debce1aca3b0efa9fa09b1c1e0e3a6cbd588690cb03cb5e5cc487c18253',
            'debian:10'           => '3beadd580e8c95463fd8c4be2f4f7105935bd68a2da3fd3ba2413e0182ad8083fd3339aab59f5f20cc0593ffa200415220f7782524721cb197a098c6175452e9',
            'debian:11'           => '22be62776fcb48f45ca0a1c21b554052140d8e00dd4a76ef520b088b32792317b9f88f110d65d67f5edb03596fb0af0e22c990a59ca8f00019ae154364bd99e9', 
            'debian:bookworm/sid' => '394478b115525dfc0886b832998cf783d7c7e6a6ee388af2482a9d491a183edeb791ab193ddb84b50112c532dbc51c34c8cad597c1f5f46635a280a03dbc9f2e',

            'ubuntu:16.04'        => 'c61b7c5e216a784eb920fbda887fa3520079073678c878cb5cb556d7b01d7d66f7a3d33dadbe2b386e0e55deea898d85540effeef930f622c2a10eaf0291d7f5',
            'ubuntu:18.04'        => '556e5036aae67cc994054142dec8b2775025bbf8fdb27cdb6434b5fb5b4cdda2628829cf8a764c31e71bbf613e4dae8d8382a16fb4f66aabea1bf486b500fb27',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        're2_2022_12_01'        => {
            'centos:7'            => 'f0df85b26ef86d2e0cd9ce40ee16542efc7436c79d8589c94601fedac0e06bd0f84d264741f39b4d65a41916f6f1313cfe83fde28056f906bbeeccc60a04fff0',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => '74fbeb57fe006f4e6c47d818ebd5bf2816c385a952c328e0231a6707160f05977d55cc45fa28ac1ee1c8c44b6f28622ce1d22452f0dc9f164866e90c87c19ca4',
            'debian:10'           => 'f2f6dc33364f22cba010f13c43cea00ce1a1f8c1a59c444a39a45029d5154303882cba2176c4ccbf512b7c52c7610db4a8b284e03b33633ff24729ca56b4f078',
            'debian:11'           => 'd64fa2cfd60041700b2893aab63f6dde9837f47ca96b379db9d52e634e32d13e7ca7b62dd9a4918f9c678aa26a481cc0a9a8e9b2f0cd62fc78e29489dd47c399', 
            'debian:bookworm/sid' => 'e74d88c10c58f086e0b6aad74045321d280eced149109081971766352a0d26460e253c6193ce70d734a73db4c8c446a360d6ed0ceb1b40f2cd52cca9660e340f',

            'ubuntu:16.04'        => '39a585e44db8df7bae517bb3be752d464da746c11f08f688232e98b68a4da83a0a83f9014879d8b837d786f021f6e99cf28fd8cadf561f2b2c51be29beb1974c',
            'ubuntu:18.04'        => '405aa75526b0bfd2380d2b7b52129b4086756d1507b04ea3416c88942c24b32e6a0c6893d9af3e3903e766fb2dbe2b48fdde7e2f355a651368c810ff3c1d2cb6',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'abseil_2022_06_23'     => {
            'centos:7'            => '671a77966a021fe8ca8f25d6510a4ddd7bea78815c9952126fcfabe583315d68ae6c9257bca4c0ad351ff15ae9a7f27c4dab0a4dff6b9f296713b4dfdef4573d',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'd9657d15987a84e857897672259f61b6939ac7170eeb66216996225652f7e0f92f97a1e20adbdcb1e24ec32fcae5283462bbdf0a4f1e0819973c7030ed9c7212',
            'debian:10'           => '5256e2da02b15e8e69aadb0a96bbffd03858f3aa37cb08c029d726627ee26b0428fc086e94d8a0ce2c6a402b8484b96b3ccb5aa3a15af800348b26ce4873068a',
            'debian:11'           => '68be5a422e7b22cc10da9daca3cfe34d33d53f18093c36008eb236b868a6e52e97a4a6b3dc35ce0a4224689d711bbbd63073653622b06cc745294f53bed7ef18', 
            'debian:bookworm/sid' => '12687c75a8cd4dc99d26963be71dd0b922194f64fa31267a40d6aed7b73de02dbf0bd2a006219abdf0021065821308d9106a6b6a4aa44dbe911299bbe9766777',

            'ubuntu:16.04'        => '2346e76308afeb174d0825921e2e0b417f268745ceef99ce38f148a00f02ca0763256025245aea56ff4f65922ab63ca037857e9b53377c6be972048e94767cb9',
            'ubuntu:18.04'        => '4e6da7f81d195e61c92189e3382021ba9180ca25e91067be91d3fb681d35804bce0fbbe7afc82a0d988a063de29895dbef1ce2c3c3a36458f64219ba7eae5792',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'zlib_1_2_13'           => {
            'centos:7'            => '649e8353e1c7ad7597378b25a81e3bccda28441a80a40d12a3e5e5bee34b88681e90157118736358e858a964b1bdc8cb1c35c6df3bdc2aeafe31664abcabb93f',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'f2d63bb2b629408166da876a3797fe4b2f71aed793696634b9653248eae0ac5ff50f39e48afb504edf08c99a9e1fe4f6568b4be59e3a2116970dc2e030eb312c',
            'debian:10'           => '8f7d5ae6b8922b0da22c94ad6dac2bde9c30e4902db93666c8dd1e8985c7c658a581a296bd160c5fff9c52c969b95aa806a8ae7dd4ee94eeb165d62a7fa499f8',
            'debian:11'           => 'f44a69f274b8bad567b197248587c35dfb1ae0a58f921075d79b0c855df347b796593435f6a0ab6af92fd1464ef0a8032e7f2e8889c7844a38a2a04705bf6f5c', 
            'debian:bookworm/sid' => '83d8a2b298fcb154a842888a28fcd0d000218919a4f28c132eb78c6a4b0f7bf10d80995a0079128957359202ed36ab01178b927a1b428bc6cf74b0bd81e81f11',

            'ubuntu:16.04'        => 'e4a3e89bd72bef42a2fdc3a13559966924361593bd03318532cbe81a5f70ef1991f8e5ab245e4740ef97deae75b907b27d9a8c4ed33d2be88ed912a31d0e7b2e',
            'ubuntu:18.04'        => '0bfe299e2d99ad9a163e1e32e1f23f0126237f171a05dcbffbe86e2d76ee770a739794e9148d25b66916ce0531eb2811da682f99b1dc9405ec7c5b88db49dd26',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'cares_1_18_1'          => {
            'centos:7'            => '65902575e20b3297a5a45a6bafcc093a744e4774ea47bb1604c828dfa2eb9a8ccd63cfc4a2bffbb970540ca6f5122235c5e19f10690d898dad341c78a3977383',
            'centos:8'            => '',
            'centos:9'            => '',

            'debian:9'            => '1f4474b79ca5f01ff4ee8edc3f25551c7d1425e691a135348a242784eafb21c625af4a189bff3275a667a61f78269f199b70077d7ff9755e8f2a30ad1ba6d200',
            'debian:10'           => '433fdaed84962575809969d36a5587becbcf557221b82dfe4c65c4a67e6736de0dfe1408e1fb8859aacf979931a75483bac7679f210c84a5b030ddeba079524d',
            'debian:11'           => 'ac55ef15730576b2e4c464775cfcfd13a67c497787d80719d524992585af9f78271d1a1e80cacb3c7566ee240cddf459cae933621fe8574d906be708fd23a40e', 
            'debian:bookworm/sid' => 'abd0c3872dd7b90f853931bb5a50dcb3f84acfecbc04e6796639ed9af240735485e8cc0e0fe2126e857a2f265d73edc4c9a0842afa0964b1522531ee56b7ed2b',

            'ubuntu:16.04'        => '8ad5c1e5cdc36b609d163cde39f87d99fb8281baf5c692f5525c3234dc8788f8f50f400cb4e2ca0e089c19275167d20e634f509d06c4d61a827ea2e4d3719dde',
            'ubuntu:18.04'        => '58fdfadf9492cba13e907f2227d3ed249de78e8839ecfecc01957d3e62c8b4c5969ac647068ee87e84a44ee853fa88367ba29fd8dab6e53a685f31e699148ee0',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'protobuf_21_12'        => {
            'centos:7'            => '82ad83b8532cf234f9bbc6660c77a893279f8ff27c38b14484db3063a65ca15b3dd427573daf915ef2097137640fa9ff859761e6d0696978f9c120cd31099564',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => '77882d112364681cfe795a8676d75d214a1030f0bf1a2e281b4100b493b8b4eb6e3c57db9f19770f6df9c3d629a43aebba446391bff299170f9ed9ee08cd0f52',
            'debian:10'           => 'b0dde2a94dc7e935f906608be5c8204393e87ba5703b78b84ad41ab690107eb306c50c9572669b0d18a55334ba26ed22a2242b54d6e30dffb1c11f8328b23c20',
            'debian:11'           => '97252bc39c9c218f02f1c5d1020296497934b1fb2ed9300c133db650ef327cbb06e5fb985234bc00ca9e86239ff2dd28b844a0eb92dedad2d4a3d88e47984caf', 
            'debian:bookworm/sid' => '8bfe22a6dec32bc56b2c042424930c18b397696fb8d67001ef38f93e1b7892fdfc947f1be1d697c9ddd245b56e029080535d385a663dc61c1f6bf959558e28c0',

            'ubuntu:16.04'        => '3bc1b533b0e67b1c3599a63510a9a95b170029ff74cff5d1960028b770631c5b14bab38e39ab0aaa4c9a5e8bdc295b671dbca2aded7e5fedc99179f8b1a0f83e',
            'ubuntu:18.04'        => '77ea38ecab665863631b2882338a7668e730d870f02377c4ceb10af1a3f91d35befd110790866ec8da6e9cd9e2cb4b88a078487b668d397b624cf5e9e2bd9282',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'grpc_1_49_2'           => {
            'centos:7'            => '4c77cf97c5c42dfddf002b9b453459ed28c8de3715145c8f162fed45f650400bcdf5c7fc714aa50b1fa14f486ae86b47d6d2cb03d00862281dda4482583385db',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'eaa6052481b1ef2535bd474caf404763a1b7b3eb85ba3ae5c0d1effee7ceb86577689e57666fbbb10bb100351ecd61e966cb72ff1ef376fdfb1ebbcb48ff1870',
            'debian:10'           => '71c6d626aaebcec2f9faa8df215ac988379ef3b7eeb2bdbef4d176d6a3534ec561fa55a4f2b69979c9cd51dcd52aa59b937718066f35cfb1cef5861f2e988bf8',
            'debian:11'           => 'bd54409a859c088e60363d5cc5afc03d2326759ba0c40e1d08a83518b0556c953830fe232945252174e69482520eec3f6f7999b85eaa417ac780dce1bd064a70', 
            'debian:bookworm/sid' => 'd83a08f2f932a232b26dd270e861e769c4007deed7fb052d19491dfcd186ebfe9218388ac89bb6d18ca333e347992302c2fddcb41b7d3d0c246c60340aa48a14',

            'ubuntu:16.04'        => '4c26236d708260d682f346eb5fb9c4c3828cd31c286f4ae95357e9e4b9a99220e29d65e7cb5ea25dd9210bc08194170863b275f0016bce8302e6d2e8a31687e2',
            'ubuntu:18.04'        => 'b885b3e7b22a1ec0d4a49d7de952a1c667eab4313c6c1e299f05969bfb194aa677bcce5cf495230087b65e25f76496786f998fdb250fd7c7826ba98164434aa1',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'bpf_1_0_1'             => {
            'centos:7'            => 'b6c6b072cef81b2462c280935852f085b7e09f9677723caf9bb5df08971886985446ba20a4aa984381c766ed0fc2d2b9cd2afaa7ab3d63becde566738058fd1d',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => 'BROKEN',
            'debian:10'           => 'e9f131ab11bf1984d19eac280b0f0f5c6161131d2b3ad06deafd3fb3c14e76f2cbfb0c3b01c88a3df05b4f2bca96d7e7934695b099721ed510c21ef9ae43243b',
            'debian:11'           => '4122539c763654fdf22dc55e7c8c4b5b42a082dac660f4779c9f1decea9b599a48bacc1f8cb7f9b859c5c520067e2d491b6b3fe9d53ea220ce8ee5eeac7cb3b2', 
            'debian:bookworm/sid' => '845aad7f4d09a05327ec16e6e35874a97ff8e63ff6ab6c3610e7ed864ade2d012c5699bf427fad88d02b621cb538e99663c46cb053903e78abcfcb82e66bf269',

            'ubuntu:16.04'        => 'broken_build',
            'ubuntu:18.04'        => 'bac4d836afc9b24d3939951f8a48a3077a1ebfe1a3523a4080fa07cda6a2bc5b48334452b4f9b120ecd17936203820c093f8ed3e900d17e23675ac686241f823',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'elfutils_0_186'        => {
            'centos:7'            => '23acf9d80f72da864310f13b36b941938a841c6418c5378f6c3620a339d0f018376e52509216417ec9c0ce3d65c9a285d2c009ec5245e3ee01e9e54d2f10b2f8',
            'centos:8'            => '',
            'centos:9'            => '',
            
            'debian:9'            => '',
            'debian:10'           => '16bdd1aa0feee95d529fa98bf2db5a5b3a834883ba4b890773d32fc3a7c5b04a9a5212d2b6d9d7aa5d9a0176a9e9002743d20515912381dcafbadc766f8d0a9d',
            'debian:11'           => 'b9adf5fde5078835cd7ba9f17cfc770849bf3e6255f9f6c6686dba85472b92ff5b75b69b9db8f6d8707fcb3c819af2089ef595973410124d822d62eb47381052', 
            'debian:bookworm/sid' => '845aad7f4d09a05327ec16e6e35874a97ff8e63ff6ab6c3610e7ed864ade2d012c5699bf427fad88d02b621cb538e99663c46cb053903e78abcfcb82e66bf269',

            'ubuntu:16.04'        => 'crashed',
            'ubuntu:18.04'        => 'bc29397fab79440a6677844dcdd550e6a157cf4c4e779c9aca5a9d38e2d8ab1e5527585e16bebf4deca765fe9afde2c1ebc1f677d2444b9b48e6bf9a2b97288d',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'gobgp_2_27_0'          => {
            'centos:7'            => 'a907b6cc247147fb2c125ee7c8186c4f2b5b57e3a114e45c53b5373324d02318aad6d3d0397aa3d9761c434f022f8a8bbb2e55caa9c5654966ef9ce85c6206b9',
            'centos:8'            => '',
            'centos:9'            => '',

            'debian:9'            => '',
            'debian:10'           => 'c5f16ad35f13555514c3a286b32909f51f9eeada3f0fd7ccba519a6faff8e1d710eb16e7d33132ed7ecc9b2477f49279eeb4cc1dd9ae62b249ffe46522c370d2',
            'debian:11'           => 'a4eb95aee0fd69c98f67d51737a93a200c87ab898786f8f18b69e1145f2316d93a55ee5c7c61de41e57f0408a9961c6e463f7d283d10d22fe3f8abdb4757d335', 
            'debian:bookworm/sid' => 'deeeff6f0a77f56846bd84c1edbe4a87978bdb40c0632074b86a27e705ce0064a4ed948934e568bbb56f24e102fce9630073391d3bdb21ba794f4e600a8c5a3f',

            'ubuntu:16.04'        => '45f99e2b3f2662aadea72c13eedcfda36289fabc3b50cbd0447cb218961a6f8e6deffb1d0f384ca9dcfb6609f4ef0dba1a5c9b0e6732a6b56a3ec6e345e1a05f',
            'ubuntu:18.04'        => 'd938f255eb75e2980bb9f14d2915b22ba9ae0f1afb0195ec57129569148c780375cab2687637d55d390a065fcd395ff4acf07602f3ceab382b3cd49bbc7b0060',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
        'log4cpp_1_1_3'         => {
            'centos:7'            => '5f314177ff82f9b822c76a0256a322e1b8c81575d9b3da33f45532f0942f5358c7588cf1b88a88f8ed99c433c97a3f2fbf59a949eb32a7335c5a8d3a59895a65',
            'centos:8'            => '',
            'centos:9'            => '',

            'debian:9'            => '',
            'debian:10'           => 'a966df89fc18ef4b4ea82cc3d2d53d3ecb3623ef5cd197a23ed8135f27ecfab2d35b4a24f594bb16aaa11b618126cba640ef7a61d7d2d22ba9682e5e0e8114ca',
            'debian:11'           => '8b695af4f89fd879b274efb93539827d73d8b823ff15a76181d2e66c8f4d337ebc92e8df090ea0d16d6bb685caf7353e37ee9b1415a64c67d30a764da649c3d7', 
            'debian:bookworm/sid' => '0203c130e64e3ed88b5d7f5142f6e07b6a66cf9d7942d16c461a6e9c45fe95c6a924ecab822a3b1863fe121972749b2c977e443f7d729a9948662546789b49ed',

            'ubuntu:16.04'        => '517204d76129ddb153a0c44a82fea512250388faa0b8ee39ac087a9dd09d04c2fae29e700364de300d63b94dcd09a85e75f7d08bbb3f7aad4cf7940b94c30bff',
            'ubuntu:18.04'        => '205e5f4601225a7fd4e58d4103a2a51dc1736361e73c8122b89c0ecaaf171245a13e3d720a144af6e36c21e9f64279d87cad46ad8c64f8d0c8ddd6c7baebe9dd',
            'ubuntu:20.04'        => '',
            'ubuntu:22.04'        => '',
        },
    };

    # How many seconds we needed to download all dependencies
    # We need it to investigate impact on whole build process duration
    my $dependencies_download_time = 0;

    for my $package (@required_packages) {
        print "Install package $package\n";
        my $package_install_start_time = time();

        # We need to get package name from our folder name
        # We use regular expression which matches first part of folder name before we observe any numeric digits after _ (XXX_12345)
        # Name may be multi word like: aaa_bbb_123
        my ($function_name) = $package =~ m/^(.*?)_\d/;

        # Check that package is not installed
        my $package_install_path = "$library_install_folder/$package";

        if (-e $package_install_path) {
            warn "$package is installed, skip build\n";
            next;
        }

        # This check just validates that entry for package exists in $binary_build_hashes
        # But it does not validate that anything in that entry is populated
        # When add new package you just need to add it as empty hash first
        # And then populate with hashes
        my $binary_hash = $binary_build_hashes->{$package}; 

        unless ($binary_hash) {
            die "Binary hash does not exist for $package, please do fresh build and add hash for it\n";
        }

        my $cache_download_start_time = time();

        # Try to retrieve it from S3 bucket 
        my $get_from_cache = Fastnetmon::get_library_binary_build_from_google_storage($package, $binary_hash);

        my $cache_download_duration = time() - $cache_download_start_time;
        $dependencies_download_time += $cache_download_duration;

        if ($get_from_cache == 1) {
            print "Got $package from cache\n";
            next;
        }

        # In case of any issues with hashes we must break build procedure to raise attention
        if ($get_from_cache == 2) {
            die "Detected hash issues for package $package, stop build process, it may be sign of data tampering, manual checking is needed\n";
        }

        # We can reach this step only if file did not exist previously
        print "Cannot get package $package from cache, starting build procedure\n";

        # We provide full package name i.e. package_1_2_3 as second argument as we will use it as name for installation folder
        my $install_res = Fastnetmon::install_package_by_name($function_name, $package);
 
        unless ($install_res) {
            die "Cannot install package $package using handler $function_name: $install_res\n";
        }

        # We successfully built it, let's upload it to cache

        my $elapse = time() - $package_install_start_time;

        my $build_time_minutes = sprintf("%.2f", $elapse / 60);

        # Build only long time
        if ($build_time_minutes > 1) {
            print "Package build time: " . int($build_time_minutes) . " Minutes\n";
        }

        # Upload successfully built package to S3
        my $upload_binary_res = Fastnetmon::upload_binary_build_to_google_storage($package);

        # We can ignore upload failures as they're not critical
        if (!$upload_binary_res) {
            warn "Cannot upload dependency to cache\n";
            next;
        }


        print "\n\n";
    }

    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have installed all dependencies in $pretty_install_time_in_minutes minutes\n";
    
    my $cache_download_time_in_minutes = sprintf("%.2f", $dependencies_download_time / 60);
    
    print "We have downloaded all cached dependencies in $cache_download_time_in_minutes minutes\n";
}
