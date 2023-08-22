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
$Fastnetmon::install_log_path = "/tmp/fastnetmon_install_$$.log";

# We do not need default very safe permissions
exec_command("chmod 755 $temp_folder_for_building_project");

my $start_time = time();

my $fastnetmon_code_dir = "$temp_folder_for_building_project/fastnetmon/src";

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
        'pcap_1_10_4',
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
       
        'rdkafka_1_7_0',
        'cppkafka_0_3_1',

        'gobgp_3_12_0',
        'log4cpp_1_1_4',
        'gtest_1_13_0'
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
            'debian:aarch64:11'   => '639d1435e732d108700b386ea5d7de5932884c1c0da0a389fab77f40c9c98f36c5c95049cd602dda502f5d73c1773bb51ac86d3ee7001762e8df78ce1809cff0',
            
            'debian:12' => '907bf0bb451c5575105695a98c3b9c61ff67ad607bcd6a133342dfddd80d8eac69c7af9f97d215a7d4469d4885e5d6914766c77db8def4efa92637ab2c12a515',
            'debian:aarch64:12' => '4eb380e6460ee87d2a030b15460648111bbb40e610a4eaed86830c5e3b3aef0f20d4a8d7625f994e976f4fd0dd1b7759d98a9cb20e9ca6bd3256677180991660',

            'ubuntu:16.04'        => '433789f72e40cb8358ea564f322d6e6c117f6728e5e1f16310624ee2606a1d662dad750c90ac60404916aaad1bbf585968099fffca178d716007454e05c49237',
            'ubuntu:18.04'        => '7955ab75d491bd19002e0e6d540d7821f293c2f8acb06fdf2cb5778cdae8967c636a2b253ee01416ea1cb30dc11d363d4a91fb59999bf3fc8f2d0030feaaba4e',
            
            'ubuntu:20.04'        => '0b69672a4f1f505e48a4d3a624f0b54b2b36b28a482456e4edba9f8085bfb51340beac006bf12e3dc90021bed627bf7d974f2bbfa2309eab12a7a062594cb497',
            'ubuntu:aarch64:20.04'=> '1bddcc9fd8ffca7cbbbd2c29f77549e7b478b8e2a282afac0fe6b234d13002135ad21555842a552f261896f1a2f656af0527f85295ab0cb60061f797e2edb1b4',
            
            'ubuntu:22.04'        => '23c01edfb5a640bd1108a112366ed7c5862b75bdd16cbe376a8c23db2d5eb5fded70e8750e9a372c0279c950f1d3adf4d53f5233371cd2acbd11def3010561df',
            'ubuntu:aarch64:22.04'=> '5578f8ffc4fcdfa13d3642ebdb990a1820fdd88670a005e59e193348c915ee7391a8a9ddbaabaac85c2a937c21f0310a8e9d89ce9b60eed0fdfba466f798e452',

            'centos:7'            => 'f7bb6b23d338fa80e1a72912d001ef926cbeb1df26f53d4c75d5e20ffe107e146637cb583edd08d02d252fc1bb93b2af6b827bd953713a9f55de148fb10b55aa',

            'centos:8'            => 'a3fcd2331143579f4178e5142a6949ba248278c8cea7cc70c977ebade1bf2b3bcea7b8115e1fbec8981042e0242578be822113e63b3dea68ae4279a63d9afd01',
            'centos:aarch64:8'    => 'd26f340a206017c102bdb5cbb6e85076cae13e7c78f0e8161f7403078fa8524ffa651d22e47fb630a6944c3655355a8b5f8ad27aaba32c71b91c987ca342232d',

            'centos:9'            => '8ee999dd3783abf99e79be4ba9c717a713330db7c17d1228c3dcdaa71c784f512d17b91d463f8dda3281ab07ed409439186d3c84385c480ed80b73fc86f0183a',
            'centos:aarch64:9'    => 'b8d18c9b682c91e1cebb0cf3b1efb2281c6bcea067261e63cff2dee076d4842db3cb213b8ef3d986e03491ddf38e59d4b7ccab5dbe9f82bb7e3d4ef9ddaa772a',
        },
        'openssl_1_1_1q'        => {
            'centos:7'            => 'ab9dde43afc7b6bcc4399b6fbd746727e0ce72cf254e9b7f6abcc5c22b319ab82c051546decc6804e508654975089888c544258514e30dc18385ad1dd59d63fb',
            
            'centos:8'            => 'c4c1fe35008606bc65bff4c125fae83738c397fb14081d59cb1e83ad5b8a69b9f80b7c91318c52613f00a7cf5b7a64dd6d23d2956c2ce083fc4c7502e81714cb',
            'centos:aarch64:8'    => '0b19b08417e3643c5d5fb7aeb327ea3ac4ea608e5297dea1eb78be69d2add48ac2a6ec6cc38dc446a84a084de13055fad8482b78ec15fd27ae0867bd3e9b2fb4',

            'centos:9'            => '76d2be30ca3afdf3e603b7690a3e7a8bf8423d4b359d928ef45f7aa827dec6d12e47c1f995c945d419763820d566590945aadf7d3ba38344b8b5d184fcc9bffc',
            'centos:aarch64:9'    => 'ab23ef0ecf1abf7badff5ae759f264ca0bf1749813b6825fbb1875040de0559d1561a97c32abb21b546229d16d81bac186ac5c5738bc3a854f4b5873a77215f7',

            'debian:9'            => 'd284915be431493b4c336d452478a28906a8268c4079fbb19c8851cf70a1a9eefe942a424e922caa4bc38eaf66b40a9971576a62ba0aebe7fd20d05b2bdeacf0',
            'debian:10'           => 'eac2b5a066386f7900b1e364b5347d87ab4a994a058ecfaf5682a9325fc72362b8532ddf974e092c08bebd9f4cc4b433e00c3ab564c532fa6ed1f30a6b354626',
            
            'debian:11'           => 'd1b1aeecbfb848a0f58316e46b380a9c15773646fe79b3d8dca81cb9ef2dce84ee15375a19df6b1146ca19e05b38d42512aed1c35a8d26e9db0ebe0733acdff9',
            'debian:aarch64:11'   => 'f701670a10f42dbf414c5ad6e36636eb5fe40610e82f5a908ca6a000daa9664055cbe6a75207626927b582beb663478e18311fb1ea32327e0c3e69284d0a2aab',

            'debian:12' => '793055b1e9cb0eb63b3e00d9e31a0f10447ffdf4166e642cc82b4fd78fd658a2c315db3911eec22fae57e5f859230fe557bb541462ae0af8e5d158295342762f',
            'debian:aarch64:12' => '23e538879279c2067d88eced2853b02aaf088ae7893bd267a39e46780108ca908b260d9952f9b7877f6fef1747c66f17b29546d2048de81e9433f1aa94f2b770',

            'ubuntu:16.04'        => 'e5af3f4008f715319cc2ca69e6b3d5f720322887de5f7758e4cbd7090e5282bb172d1e4b26ef88ca9a5212efd852658034ddac51ea86c4ca166c86e46e7d5809',
            'ubuntu:18.04'        => 'ec1dbceef7c3db5aca772f0ec313a9220ead22347957e8c24951b536477093d6561c3b6b2c9d1b876b30b52f793b5b3ab7dc8c4c9b6518f56d144e88cb4508e9',
            
            'ubuntu:20.04'        => 'cbcccd25343826ac62e36ee7e843fb701be3d4e3a18643166d163c1d8aaf6d1b932f48161cbbd218a761aca89f72fc8dbfca7b329aa1e39b4e556364041ba242',
            'ubuntu:aarch64:20.04'=> 'fd759a8bdbe107ab396c97b0c2bfd59045e7f5aa5e996e5d13d518cc491122fb22a4fbe3e59167bcb99ebe8b2fc676bea92755a2e1d6f4b483b69cf9b72e0cdc',

            'ubuntu:22.04'        => '40c8edde5b5798865190775336139f7f5c617bbde8d9413ef32382c10097eb747f5574ee3c672aaccaf1703067307cf6e3f7eae1340c45f0f6f2ce0dc3c899c8',
            'ubuntu:aarch64:22.04'=> '303c01b34d86609341dfe6a77c6c0d51192ba654d71a142e2a1ae42c8085073c489586c6fb743f20a18f4d1128001cc15eb2a5d98c6523cad1bfbaef0bed089c',
        }, 
        'cmake_3_23_4'          => {
            'centos:7'            => 'f19d35583461af4a8e90a2c6d3751c586eaae3d18dcf849f992af9add78cf190afe2c5e010ddb9f5913634539222ceb218c2c04861b71691c38f231b3f49f6c5',
            
            'centos:8'            => 'dbe18cd4555aa60783554dcd06d84edac69640d15ef3ec7b4e2ff29e58b643fa8a0bcc2b838d6ae3c52a45043382e40a51888eaf1b45b2de3788931affc9e1c7',
            'centos:aarch64:8'    => 'bfbed76e9dd3cd64860001f500c413700ef9f58da44ff742b277bc1948df4c92bf574a62ac5a498e32991ed56f8e52837d348fcc89eae5afe2a580c4a267caeb',

            'centos:9'            => 'ffcfb14f224b24b67ca68edcf36b24d8dc6ddce47dc597ccf4d13301ce7d87e79c9fec67197ce1ee57b9acd8bde58633418b8c1eff1a85300a6f7af033263d2c',
            'centos:aarch64:9'    => 'f34540fc160b197b89f9a814794d4abdf3b9607fa1af5a81f9bd9478a3ae460799f26f35e433cd650f8857232b0251d18db6152c7782fc1e7ba2008d272cf685',

            'debian:9'            => 'd23bc4b5e5b8ab39ecb2046629a259265ea82f9247785c4c63cef2c11f0eb8064476f3d775a5b94ce0272f9a3227f2b618d87dae387840b69e468b9985416398',
            'debian:10'           => 'cab3412debee6f864551e94f322d453daca292e092eb67a5b7f1cd0025d1997cfa60302dccc52f96be09127aee493ab446004c1e578e1725b4205f8812abd9ea',
            
            'debian:11'           => '9aac32d98835c485d9a7a82fd4269b8c5178695dd0ba28ed338212ca6c45a26bff9a0c511c111a45c286733d5cdf387bcc3fb1d00340c179db6676571e173656',
            'debian:aarch64:11'   => 'd5ce7b39cc0cf287a0e006928ff8e9da094664d6df5848cbc8b437284bfd916c9a9ce73aab115da3850a7a207cae1b8a4fada3a0bc97ab2e57900b6baf9594d3',

            'debian:12' => '9f08c5776349b9491821669d3e480c5bbd072410f4b8419c0d12ffbf52b254bddb96ee6e89f02e547efcf6f811025dbbbc476e2506f3a30c34730d72ad1de656',
            'debian:aarch64:12' => '40731965cdb6d3287a88dd0fe5a380ecdab92579d2e1ecc2bb75d1eb95ae0102822e08f0a5b1db0024dfc3651c66c30b332f7c4291cf80bab875a34f59af5c23',

            'ubuntu:16.04'        => '0b89bae5f0ed6104235c7fd77c22daee42ad15b8a7ce08e94c2f6bebdb342e6e5672c2678d15840a778fd43c7c51fdc83f53a70b436a79c2325892767d2067a1',
            'ubuntu:18.04'        => '1d0c06bea58cba2d03dbc4c9b17e12c07d5c41168473dee34bfcd7ab21169ab1082d9024458a62247ae7585cf98c86d8e64508c3eab9d9653dee1357481fc866',
            
            'ubuntu:20.04'        => 'f2bc63e9813ee7e233ca192ccd461776166992f3357500d30318dc9314db5e24f39b7e56f7a5d813c0ab3802bb48cd2c651e9c8bc68c3f6d6739b14a1412f6ac',
            'ubuntu:aarch64:20.04'=> '367183c8f2eeb6b5d98694733cfe8033c3511765634dafa2f06e00e0460c74b82ee3045a7a59e1df5b0dd74999377156c260d01c5a498362942fb9ef5d89929c',

            'ubuntu:22.04'        => '8ee9c1ce4f82434bf18473a7910a649afd7132377a15c7ed12e3844d04b5d804e92be2cccb5b6c6cbe46459f8d42bc1ff09f4e325f7b5c1c2542e31552f0bd09',
            'ubuntu:aarch64:22.04'=> '6c22838bcf91e31e54ed9a1b015019d84d2b527205dd07be970bd6190d3b9be3a54cee83a1a94138cb5abb264b36e0d1e397feb1fdaf35c7c2529f58162699a4',
        },
        'boost_build_4_9_2'     => {
            'centos:7'            => 'd395a8e369d06e8c8ef231d2ffdaa9cacbc0da9dc3520d71cd413c343533af608370c7b9a93843facbd6d179270aabebc9dc4a56f0c1dea3fe4e2ffb503d7efd',
            
            'centos:8'            => '7e79ac11badf496a70af00f87afca2f4cab915b017f06733bd5ba4524d1083f22c5a89a46ee4bad97aaf2b5bdefd65eb92abe63d4857618ac8af1a068700ff18',
            'centos:aarch64:8'    => '8f25c3ae1cb8334fcc8f9db739374ce0dab760311309897eadcd567cab3d7695bc53d901189975a1d48bf8e5c040ea66331be040bb7599f0040f4b786d151f64',

            'centos:9'            => 'fb604dab4188dfa7d81483274fe30daa8ddc27bd8ea0ba37eaf7171db781f397750ab8a27edb160895307ee5e5c89f3b59478cb7f40e7e6113513c76965b6c21',
            'centos:aarch64:9'    => '4cf47707e4e542cab65f3482bf8ba76462d263c14369bb675f7bae9f9c70e880286138cd258de28de050359350f464a829bdf8e4ded5394a1bf3808be7df5cd6',

            'debian:9'            => 'ac536be94ec5133c45f4d435dd082e1ee7299bce7ae971e361eda716466963be358452ff0c959d7e610a05b03dbbd41ce195be4ee6023b8b223f6cdb22cd0c67',
            'debian:10'           => '89c1a916456f85aa76578d5d85b2c0665155e3b7913fd79f2bb6309642dab54335b6febcf6395b2ab4312c8cc5b3480541d1da54137e83619f825a1be3be2e4e',
            
            'debian:11'           => 'f434ddf167a36c5ec5f4dd87c9913fb7463427e4cda212b319d245a8df7c0cb41ec0a7fb399292a7312af1c118de821cf0d87ac9dcd00eed2ea06f59e3415da2', 
            'debian:aarch64:11'   => '8615b98a0e078fc978d05e7288272f63c06c2aa21c5ed8bb3b4a52c504bf0ccc839335ed2c216d97fef01a061fd41dbc35da4ad2253690968dcee36d9a843d1c',

            'debian:12' => '283835e4cb70db05f205280334614391d932bea4dc71916192e80f7625b51aade7b939f4a683c310f49d7fbcd815318b261d8d34668bb3cc205015448dc973b3',
            'debian:aarch64:12' => 'df6153bc3ac3677a1772af3af590ac421a0f4ab0999afe8480cf48a79c7a7bcb2f05b4e28f9c844dda707c03c7f2b54ec7d98abd46c62792026323cee0607d1a',

            'ubuntu:16.04'        => '0361e191dc9010bbe725eaccea802adad2fced77c4d0152fc224c3fd8dfc474dd537945830255d375796d8153ecfb985d6ee16b5c88370c24dbd28a5f71a8f56',
            'ubuntu:18.04'        => 'bc4287b1431776ae9d2c2c861451631a6744d7ae445630e96a2bb2d85a785935e261735c33a4a79a4874e6f00a7dd94252bc5e88ddce85b41f27fba038fea5a2',
            
            'ubuntu:20.04'        => '58ee3e5b8f6f58f1a774c7269c64a8dcb4f5013748fa11a2adab4e97b55614c867fcc37b536b6fcbc9c3eea678b356c26ae0e3a59284b06e5222b003c2636e16',
            'ubuntu:aarch64:20.04'=> 'ff27410a164727aadc7d9f0816ecef2fb541d22d7b1bb75d055adc5acf4518b40dfc4ebd34cf2c21dd5a00abd039d005dd2c142e6f85ac6335e61d5912c3e96e',

            'ubuntu:22.04'        => '4ff59be5acf032c11bd1c52bbec7276f7dbec08d271ec1f580af76fa8f12185213640491fc218d99e754cd642367c261759002d3c49be531da20292215bb6746',
            'ubuntu:aarch64:22.04'=> 'c77ac38d6c9d5e28beb0a96d2228efb4392a081d2a8495d729bc7cc8744c69f8a08ebd971b1e66ae83dca8aa84e866cc4f7ec27e1da4402f8fb72e732588f09a',
        },
        'icu_65_1'              => {
            'centos:7'            => '4360152b0d4c21e2347d6262610092614b671da94592216bd7d3805ab5dbeae7159a30af5ab3e8a63243ff66d283ad4c7787b29cf5d5a7e00c4bad1a040b19a2',
            
            'centos:8'            => '0f3bc9c55e93956ce39c044cb99b4eaff8b69365c69ce845a56ff00ec32cbaeb84ccc9b37757f8024c7c7a1fffcc0e61ee4d8eeb226ac447a2d9718b5667e052',
            'centos:aarch64:8'    => 'ca3e6ab76206e6efb2d891ec7c9a540ffdc4ef954e46c6ca88f3c9e4ac6bcccf4e62f82eaaa60e9c21193ca5b574f9737f2aaa04034803f07133f65878b7307f',

            'centos:9'            => 'ebc4041781e7886d4c2526469bbe23849711b9c9b3e209ff16640dcb0d9c3c874a4958a6a4393c47b0ef8b188bd1ad74aff04ecf82c0214f6d7c4b08549e02af',
            'centos:aarch64:9'    => '30e9be25c9f61c9448fcd567420af034c2d51797630e6df596b2f6b8b0ff9bf72ccac83437fe0f576d229053ba45338ab0d2aa891c29b73bf7b31b5bd834811a',

            'debian:9'            => 'bdf9c89926d3aff1c5b65d20b94b2bddece53841732349bcb15f956025f950809e0212841712f21b52c5286c513066c01fa025a0e06ab9feee9bef8f7b74372d',
            'debian:10'           => '1c10db8094967024d5aec07231fb79c8364cff4c850e0f29f511ddaa5cfdf4d18217bda13c41a1194bd2b674003d375d4df3ef76c83f6cbdf3bea74b48bcdcea',
            'debian:11'           => '0cca0308c2f400c7998b1b2fce391ddef4e77eead15860871874b2513fe3d7da544fdceca9bcbee9158f2f6bd1f786e0aa3685a974694b2c0400a3a7adba31c8', 
            'debian:aarch64:11'   => 'a1926f3528067b9a5db29da4fcca52da62114e1f0763880595ad455ce6025788975325abd974cc9e8b17e0769c16211dafef91160e2d698e955769475766d51e',

            'debian:12' => 'de03047ca1326fa45f738a1a0f85e6e587f2a92d7badfaff494877f6d9ca38276f0b18441ebe752ac65f522e48f8c26cd0cfa382dd3daac36e7ea7a027a4a367',
            'debian:aarch64:12' => 'd1afb4ca6d0361614bafebb4ce2c36e7e0acc054d1bdd6dc6c516c908160d1ad9cb6d5b99d4792d4e8a9e9c0a888825e252d00d7c94e6b63bf79c00a1a18e58f',

            'ubuntu:16.04'        => '4038a62347794808f7608f0e4ee15841989cf1b33cab443ea5a29a20f348d179d96d846931e8610b823bde68974e75e95be1f46e71376f84af79d7c84badeea4',
            'ubuntu:18.04'        => '549423e7db477b4562d44bbd665e0fb865a1b085a8127746b8dbbaa34571a193aaa4a988dac68f4cd274b759200441b3d2a07ae2c99531d548775a915b79bb61',
            
            'ubuntu:20.04'        => '61b69192e6d96d5533339cd2676b120361031d41de4016ef7a013dab60b01385c6ae5427af74749848e2198f375b0d6585f0e63960a34ff49218b65c9a93e055',
            'ubuntu:aarch64:20.04'=> 'c72f5910ec83088f8646368a543e040751b57881797ec9892a89b53d1bde6da8d3c4829a6b531b0c7d5c583dc526e9a4588e062ba8a4df70340dcee4a97a09c9',

            'ubuntu:22.04'        => '00f10b4edabe8c7415072432e55046633c3406c8aadcfb6d59dce950c7c0cbc116766fcd84e46b49415b1e0a65289cbf7d83282565e1bf37f38bc45c1812eaf6',
            'ubuntu:aarch64:22.04'=> 'efd3e5a1090b9aa670a41ad67e2212d690bf6de05d6eb2c66fb9e7b6c1d9c5760477380a708172f4511e556a78749516cf7209a376322ed1ed3bbef749a014b3',
        },
        'boost_1_81_0'          => {
            'centos:7'            => '403c89dfdfe3ef979f2f742b9a199a3031426ec6c10a0b1be895e5876240e5b636a33b590dc01766acbebe36ff9b6c7175523be2d95097ac37994a346081b343',
            
            'centos:8'            => '0e57552be3ac0d753838628d38485826aa402b2ac752ea1d546994bee3e9d689b3b439e652285f30f777cbc4e19a8217923d994079f243e8a3e4d4f354fa865b',
            'centos:aarch64:8'    => 'b96787606728aa663329cea0022fd33fc39344e82277e5b2869167e8f628560390f8851ecf663f4bec17181034493000c941e607ac3f9a484fe04c391bf1cc74',

            'centos:9'            => '3e9ad8d2032b5eda9bfe9a1a151f98545ae78cf6422dd307c733507554d4cd23a5d7b30d44552a15c66c0faa25ab2146fdf5a14a2cf360efc5c49ae17ddeb0f1',
            'centos:aarch64:9'    => '4e1d337d3193b6e0deddd8351729d7bfb145632b7b1c1388b613a55259ce0f20a3cb5e27c039f67143c277c39148e5bfff20cedc1246e8d4b13e7b73473a43a4',

            'debian:9'            => 'b2bd35fc71d6e00bd35d3ae38728fb5312ed53cbcfb7ff4544281a5016f62961cb4b8371aead26c9964b4cf483ae9e6ee5beed003b7f9d26ad40c90547439795',
            'debian:10'           => '3b146de940bf36ea301c2078edc8dead611c4a770643c548080ecfdf8820856b23fa73a15fcab0579550cb19ad816fbef6040ad98ee500a8d15a66ed99eef241',
            
            'debian:11'           => '6e8a48ce6874e5f12b1734e590c726dd53801a5193e71cc505ce2bf9e558318fe970bbac1c8e50938798e0c86a9314ea32268ce0e817cc4a6023f46fd6e011ae',
            'debian:aarch64:11'   => '75037fee14a63a62a26a7405a9922b1477b431187dedc9376de25addff910b99ea5e229b2169f5402b155d2a948fb0c311a9ef527756d5e1cb68205187af5d40',

            'debian:12' => '9b4cf7bb2a002559b95f83487723d1d4f99277fc0268454367bc6912ffc41256a30c2e211fb66bb57e50909c535cefcedd611ab27aea373166db6c124d6a9d80',
            'debian:aarch64:12' => 'bef2af4e6b7971dbc49a45a81502dd379ae2d3c179812398f629ed3d7e01c1bc4dd479323c3aa300c29a9f8c0c8a132da14862543feca49ad288d96926f188c7',

            'ubuntu:16.04'        => 'f9c9b6141d554529f8386412c20873758974798e646bdbd4a5aea4c35af8183057ae34930d3d59f296bd94db970fa42abb07555407d339f8aad07b1a2bd7211d',
            'ubuntu:18.04'        => '35092c1acad174667ca67cec6cc55b3a2944d194d16e669c261c65dc73f6e328cd7d0fe33e17d8cfd25f781e34f9b9438c8b1e0ccf24b546b17f949791082dd4',
            
            'ubuntu:20.04'        => '7e82d809ef02ceb3f9392cba59e11da05f90dcbdbec55f2d9b7280bfd987c5dfb3b7252d47cf2510d5474be0d0975e359146b1b2e6995bd0f721e707222fc27e',
            'ubuntu:aarch64:20.04'=> 'b5c2f87237b7142200eba5ef45104a76110623075ea7fc29d483661a5635e01d2070cbf15102b621d76f030403a2ae4dfb7a0136739dd2211cf3461e7311c9c6',

            'ubuntu:22.04'        => '3fb3bc947a68dc84d6eebf97daad9f1e93ce21a8bf4286fd786e2fb55f78faef5c12969694f61e9255187618fd3d2e16ed96a17450a08a9cb41b67e18f025977',
            'ubuntu:aarch64:22.04'=> 'b1df2e2ce44aaac8d0c3f66a1e9c9eb612e20836ddb815e6b91eec9ed48089752d8e5910a2b57edccaf06667fce04642e5867b36bf37c6614df07a3419877f70',
        },
        'capnproto_0_8_0'       => {
            'centos:7'            => '5c796240cb57179122653b61ee3ef45ca3d209ad83695424952be93bb3aad89e6e660dba034df94d55cc38d3251c438a2eb81b7de2ed9db967154d72441b2e12',
            
            'centos:8'            => '27a2b5128a4398c98e65af1c00c7deae62a472b3b0c01bda96e6903d77974205f2cc6f1dddbe57cb39b3f503fbf466caf255c093d0b0c123e28850f517f0272b',
            'centos:aarch64:8'    => 'ddf4e19c0655b768a80c9e680e4ddb1cfe05fa606e704912a0b9d467e031605457d679756de23c13c935e9a45a5d770128d8d3cfc592d5ab758860f236dac574',

            'centos:9'            => 'a4cfb081e1b08b41dc0d51d62e9136826b313c65c773afc2942da09d096f0e07d109be500313ea6cb6d241ff5737f2d6b51a85526e8495afde45fdb2e89f8953',
            'centos:aarch64:9'    => '1ec4a4473e217eb6a0ae2d1c5026283f0f08811c70fdf14b658f467ef5ddfb31d18dffd7c763cf535288b6a3988831dbacc4ed58b69bafd333b35057d7eac6c8',

            'debian:9'            => '7c6b3c073ab6461daef783ab08d367df56730764bc43d1c2a66d6a4001744400a98adf0399326ceb303f2d609c206858c311300eb06b252bf899d5a5616f142e',
            'debian:10'           => 'e9ba7567657d87d908ff0d00a819ad5da86476453dc207cf8882f8d18cbc4353d18f90e7e4bcfbb3392e4bc2007964ea0d9efb529b285e7f008c16063cce4c4e',
            
            'debian:11'           => '72c91ed5df207aa9e86247d7693cda04c0441802acd4bf152008c5e97d7e9932574d5c96a9027a77af8a59c355acadb0f091d39c486ea2a37235ea926045e306', 
            'debian:aarch64:11'   => '82b411ab9a2f80415eb5c396d933a88aa9481042566fe1708b214d087a77bc67e17d0544c721f3f6b254ef6685a843edf71aef0ff44f697bb22417279ed1bf11',

            'debian:12' => 'aeeff7188c350252c9d1364c03c8838c55665fd9b7dd5ebea1832f4f9712196027bfa0a424f88e82449f1de1b5c4864eb28877d2746f3047001803974bd1e916',
            'debian:aarch64:12' => 'e72adadc01ddd626f398992cbcce291432a587a8e86340ece77524b5a1cfb0ba354445c14b3422c501f914c700fe78a14e1d01bfbd9a476fc061cb7bc3bf93ad',

            'ubuntu:16.04'        => '5709dc2477169cec3157a7393a170028a61afdfab194d5428db5e8800e4f02bd8b978692ae75dae9642adca4561c66733f3f0c4c19ec85c8081cc2a818fed913',
            'ubuntu:18.04'        => '3c1281ed39b7d5b8facdb8282e3302f5871593b1c7c63be8c9eb79c0d1c95a8636faa52ce75b7a8f99c2f8f272a21c8fc0c99948bbf8d973cb359c5ae26bb435',
            
            'ubuntu:20.04'        => '916ee7622e891517b35134d3418dec0e33be54f8343418909f2659bb11f41d96a97d61c02fc569960bc4dafd5e11a2f6f7a22d7d3219bc3ed49c47ab6b47f5c7',
            'ubuntu:aarch64:20.04'=> 'c0ea2e83a1d5bbb170a9432933854404b25d7af26c860057548e6fa67e8b4372fcc82895e982dcfe1a835439a52f07300d41457e108657e00158713daaac0135',

            'ubuntu:22.04'        => '3260ffb9dc13aac6e045480ec3f9b7cdefef30b1446ca298ab6b3cd8628192f1bb6422b8c02a7fecbf5d65038dda3985cc40773c699c49b01afcd50d1395be9f',
            'ubuntu:aarch64:22.04'=> '9f29fd8e1ee6065929c0fc6ab1c39e924a4a9062d4a2fdd060a03885f26d30927d538e6d7cdfea21f1577fb6259c53e7bf25148ba250226f0dff0f6dcd5e1ece',
        },
        'hiredis_0_14'          => {
            'centos:7'            => '03afc34178805b87ef5559ead86c70b5ae315dd407fe7627d6d283f46cf94fd7c41b38c75099703531ae5a08f08ec79a349feef905654de265a7f56b16a129f1',
            
            'centos:8'            => 'ccd1828c397ed56e4ea53dd63931bddd24c0164def64ceedca8d477eb0cafd7db12ae07a4da9584331b1af9ef33792da1cb082b3a93df9372df5ad233c5f231e',
            'centos:aarch64:8'    => '18e39412a6c8fd9bd7f2f07858784a2d7debca92ce71290bc2c6269443f53919d29ff3f3b6785d637a893da3bf0f409e2160297007546a46984ad5f3980c4ed6',

            'centos:9'            => '304e402b1a86734095476024840c0ba8a0ccf98771ac9655672671a7b264ee73a87a2043ce96ee8acffa12901f75ca5403dda297c040b8b3cfd220979df472c7',
            'centos:aarch64:9'    => 'aad8b76882dff7b92891647ed596e0e4ac12930f37f7a7ac4f81f6600c0e289ba0adf82bcd0480969ea1e1dc66ee9e9cd9531227ecd6ca6757bc34337a4c187a',

            'debian:9'            => 'dae76b5ff1749f9b28af8b2bb87e36879312bad7f6ea1f622e87f957eb1d8c9ea7eb4591a92a175f7db58268371a6c70de7d07cbffa43e763c326a08bbf09cb9',
            'debian:10'           => '76ca19f7cd4ec5e0251bc4804901acbd6b70cf25098831d1e16da85ad18d4bb2a07faa1a8e84e1d58257d5b8b1d521b5e49135ce502bd16929c0015a00f4089d',
            
            'debian:11'           => 'c0effe2b28aa9c63c0d612c6a2961992b8d775c80cb504fdbb892eb20de24f3cb89eb159c46488ae3f01c254703f2bb504794b2b6582ce3adfb7875a3cb9c01c', 
            'debian:aarch64:11'   => '5fd2dd3afb0f85917b6c0760d7b97dc803d30caa3105f1bf7c7119e025ae4a843ff1e69507980a178219e89d246c586cbbf8dbf0f0168946d5cc1c2ababbc81b',

            'debian:12' => '0fd3ccfecff6eea982931f862bdfa67faf909e49188173a8184a5f38a15c592536316a202a1aada164a90d9f34eca991fee681d3a41b76a0c14c9eb830e60db4',
            'debian:aarch64:12' => '81d16b6b58d785c6beb7444cf75523615511c19316f5c1d5b019524d31db10ca17e4da8b5bd5a5495c493ca5a0c10ccda71240e4d85561681070b0c525003c6c',

            'ubuntu:16.04'        => 'a8fbcbcded98a70942590878069170ee56045647fbd1c3b1a10bb64c0b4bb05808d8294da10a3d9027891fa762faabdf0a4b70a72a10f023a83a4b707b9a7b5b',
            'ubuntu:18.04'        => '5171604d9e0f019c22e8b871dd247663d1c2631a2aa5b7706bf50e9f62f6b1cef82db2fe3d0ff0248493c175fb83d0434339d7d8446c587947ab187fabf5fff4',
            
            'ubuntu:20.04'        => '0e424f586b402f83fcca02ebdf11dbfdd6885788c7364c8957970e33c5175093e78d754d1a35f893744c8e067d20267501e73c18a2ece6a2751c46b954f18f8f',
            'ubuntu:aarch64:20.04'=> '786b33655f8f5e18a1df177482c88b36954dc22e3ba35a34342334eadda5ee9edc1e44a3134aa560b5ab2b2d3ca193056848568fd8868d968b1b34e0134b8762',

            'ubuntu:22.04'        => '62fc6659b6ae7e6d6aa573cc810b8c14d01dbf1153913ae8a929e51676813b71ce38d77d7f7f8746a3ccd8c303306c8d0a5cd84faffb78880be425aabd90e200',
            'ubuntu:aarch64:22.04'=> '3852674e4d8fb58ccfccda3e1509216484a437155f70590fb2b5bc45c41dcbfd2adc16095424806335ffbf4f285588defec36fe97b1edd8baba628daa70b3ece',
        },
        'mongo_c_driver_1_23_0' => {
            'centos:7'            => '8ea15364969ad3e31b3a94ac41142bb3054a7be2809134aa4d018ce627adf9d2c2edd05095a8ea8b60026377937d74eea0bfbb5526fccdcc718fc4ed8f18d826',
            
            'centos:8'            => '99f69f62622032f4f13dad5431529e4f0e69f02de0e23f74e438a2a3677a61a33e649b7384b242857401776a2162aec9478b5ce3658b9ce0b9e27f8fa61f625a',
            'centos:aarch64:8'    => 'a33fb45aae3fba3c0f2c5e5efdf9e8f1ba09dbefba0368f0316dd536130384fcdb7c2248a38adbb0b3594e31c7f66a897a3a5571a51c537b7f25c8b6232e5cc8',

            'centos:9'            => 'b1785b2bf23c8363856b8131732577ca955d66d346716a6d5c2f306042fc25d4cfd9ba320dcdcaf34ec810b1eb7be585427f382acbdf99589b84dc246a85871a',
            'centos:aarch64:9'    => 'dd575c403085190ee682074c8a826ee4c38ba91786bedebead80db149df228a7a80ffc93a9d13167f7fe29b2a43d653f4f6ee3123edf52dac5a20b1058d3ba8d',

            'debian:9'            => '5b41952d68747fbe4d402b2f5be29250e68936599fc0254cc79c4518548b209056a24debce1aca3b0efa9fa09b1c1e0e3a6cbd588690cb03cb5e5cc487c18253',
            'debian:10'           => '3beadd580e8c95463fd8c4be2f4f7105935bd68a2da3fd3ba2413e0182ad8083fd3339aab59f5f20cc0593ffa200415220f7782524721cb197a098c6175452e9',
            'debian:11'           => '22be62776fcb48f45ca0a1c21b554052140d8e00dd4a76ef520b088b32792317b9f88f110d65d67f5edb03596fb0af0e22c990a59ca8f00019ae154364bd99e9', 
            'debian:aarch64:11'   => 'f3431068b375c7b1746ff0809ad41f9b0e9a7b28499420dd432df8d5cc3c9545b1046542959f4b9ec9ae32659d9d4beafbe8ac735e35b0fdf92c169f90f1b6ce',

            'debian:12' => '394478b115525dfc0886b832998cf783d7c7e6a6ee388af2482a9d491a183edeb791ab193ddb84b50112c532dbc51c34c8cad597c1f5f46635a280a03dbc9f2e',
            'debian:aarch64:12' => '3329f2d800509a4c87a4985994952951fda8ad1c0425ddb963ebf16f5a2138c5a4c7b9353eede89c5b23804beb2d185decc1d2e489cb63774a599a761dcff34e',

            'ubuntu:16.04'        => 'c61b7c5e216a784eb920fbda887fa3520079073678c878cb5cb556d7b01d7d66f7a3d33dadbe2b386e0e55deea898d85540effeef930f622c2a10eaf0291d7f5',
            'ubuntu:18.04'        => '556e5036aae67cc994054142dec8b2775025bbf8fdb27cdb6434b5fb5b4cdda2628829cf8a764c31e71bbf613e4dae8d8382a16fb4f66aabea1bf486b500fb27',
           
            'ubuntu:20.04'        => '319768e46ae4a308700033f64953966ac0e6544712d683305b6c5621542decad3e240f22afb7b83bacd6bc90766be342278de3a3643e092cf26ae7d784acfed7',
            'ubuntu:aarch64:20.04'=> '9a71aaf2197b99f3fa00466441802a57c4aaa29131673565830c4d0bd3719beb9ac2918b062ff9e0a81949fecac6ca2b637780b1e4f05c91e7e92a9e7dc14ce9',

            'ubuntu:22.04'        => '4661c4c0c75d54d7e07ae069b8d2d1174bf06df95c1a7999f927e9b29ed251bdb035290668ce24efe60dfa944eca266e43655fde6873e5863951d8d21bd629a6',
            'ubuntu:aarch64:22.04'=> 'e0a342176ccc26bf2a978f160b04046cf5a1bec35b7eaf85574b3f76196f29354dbb8eabe86326d7a1f93ce6805e18127462f7048ef7e8c7d226c1d04e4241ba',
        },
        're2_2022_12_01'        => {
            'centos:7'            => 'f0df85b26ef86d2e0cd9ce40ee16542efc7436c79d8589c94601fedac0e06bd0f84d264741f39b4d65a41916f6f1313cfe83fde28056f906bbeeccc60a04fff0',
            
            'centos:8'            => '57a0442b035767f163559b31a76c2f59285d3605ff078b17aae45a8c643d22f7876ce707d0d2b9b23791f8059921b5334e9b6860718e46510a0aedf05ffbaa58',
            'centos:aarch64:8'    => 'e9ec5ab3a71770d77b0b758167687f9ff923e75388372146f11ad4cc3bc3cb24990f77ef4fd34c81c1eefb3674160f69bcc0775a4d151da9c4ab9538f661afa1',

            'centos:9'            => '24ceda96377155a57fa6161def14a8dc7daf10f825fb97f39fcf434fece8b4efe7523e91cae6911f6b58753e73e47547a01488498fd16e7b4c64764682a2313f',
            'centos:aarch64:9'    => '7d4210d404b9e0e244cfaf234a09d81bf15e0c63f68159bc90afb4c732a4e1e5e85e94e5b1a2dd67f9766b47f28c9a8e4662106722b2ab95fd5df9be1070021b',

            'debian:9'            => '74fbeb57fe006f4e6c47d818ebd5bf2816c385a952c328e0231a6707160f05977d55cc45fa28ac1ee1c8c44b6f28622ce1d22452f0dc9f164866e90c87c19ca4',
            'debian:10'           => 'f2f6dc33364f22cba010f13c43cea00ce1a1f8c1a59c444a39a45029d5154303882cba2176c4ccbf512b7c52c7610db4a8b284e03b33633ff24729ca56b4f078',
            
            'debian:11'           => 'd64fa2cfd60041700b2893aab63f6dde9837f47ca96b379db9d52e634e32d13e7ca7b62dd9a4918f9c678aa26a481cc0a9a8e9b2f0cd62fc78e29489dd47c399', 
            'debian:aarch64:11'   => 'a8356a05a5608671f89fdfd4521fcf560885efc77d57f4cf13c02f309ffbc291f4365d8f3fe82915198c1812032d287300a6dec9ef6c72bd6a6ab5c99ba6e8bb',

            'debian:12' => 'e74d88c10c58f086e0b6aad74045321d280eced149109081971766352a0d26460e253c6193ce70d734a73db4c8c446a360d6ed0ceb1b40f2cd52cca9660e340f',
            'debian:aarch64:12' => '48fcfd4e912d909ec65360ffbc53ac623d351384bdc79c92345637bbc07f7f5c03e3d7d47832d2478c12b638a2f23e52373f8d09fbc9c49910af3d780d940d56',

            'ubuntu:16.04'        => '39a585e44db8df7bae517bb3be752d464da746c11f08f688232e98b68a4da83a0a83f9014879d8b837d786f021f6e99cf28fd8cadf561f2b2c51be29beb1974c',
            'ubuntu:18.04'        => '405aa75526b0bfd2380d2b7b52129b4086756d1507b04ea3416c88942c24b32e6a0c6893d9af3e3903e766fb2dbe2b48fdde7e2f355a651368c810ff3c1d2cb6',
            
            'ubuntu:20.04'        => '865f3472da0070fe3aea5fed5f98d1e6e42c145045941be19eb324d39ff558f92c281194760d59c37d7a306d5d59e08989ae35ba63d3624981f20bd73fe2a7a1',
            'ubuntu:aarch64:20.04'=> '064090aa565d7fa244819dec20939b4ac790d8bae4b5cbc160249bfb3d50b6d52c447c3483692e5bb2577c5d6d863a05c6eccb309943c5a49d90cd603be4bed3',

            'ubuntu:22.04'        => '6cda2a6653881a8a06af7f7d4b8e16be09bbe5e3ce463a2e62d8f479aa028e81e7eb8489035b55dfedbe5dd223a27f4673337073a216062d7499992153448a5b',
            'ubuntu:aarch64:22.04'=> '530bd200ab98edf4fcaf74f407ff53788a0de676a5a383eef067e819263945bb5e883029a7ae4596b72542e6b7a17af3128592cab8f519dd6d646cd7e6bd5b54',
        },
        'abseil_2022_06_23'     => {
            'centos:7'            => '671a77966a021fe8ca8f25d6510a4ddd7bea78815c9952126fcfabe583315d68ae6c9257bca4c0ad351ff15ae9a7f27c4dab0a4dff6b9f296713b4dfdef4573d',
            
            'centos:8'            => 'a81445b63bcb97541c39a1afdc330ad15840cd8fdc1fc004ac934cd8acf4b4a50a0755ed8a0e7e64c4fa6f3d99725fc67b9d35f4da4753c597a37f6cf0d0ee5d',
            'centos:aarch64:8'    => '421aecf02072129c92e47e91edbc550d2cb399d5aa8eb44021262f72d3aaecdb8247d4936a6452af7b48d5f23434d55e9df3927912357a58e05d972896d8b347',

            'centos:9'            => '247dfe1699a3bb00e57fe3764d2a69f452f4fabf887c8a0134b73afb5516996518e631c23d59fa998cdf992e6e4f364adb54b3479d6bc4ebbe868d21655e1235',
            'centos:aarch64:9'    => 'c8f7e9a3e065de4c56736fea43d7f55d0fa2e1e2104688616c1bdb5b018d1faed601c00da3207b4b785acd5ec1a6182c015f1897f7e164884eaf84ab52a06607',

            'debian:9'            => 'd9657d15987a84e857897672259f61b6939ac7170eeb66216996225652f7e0f92f97a1e20adbdcb1e24ec32fcae5283462bbdf0a4f1e0819973c7030ed9c7212',
            'debian:10'           => '5256e2da02b15e8e69aadb0a96bbffd03858f3aa37cb08c029d726627ee26b0428fc086e94d8a0ce2c6a402b8484b96b3ccb5aa3a15af800348b26ce4873068a',
            
            'debian:11'           => '68be5a422e7b22cc10da9daca3cfe34d33d53f18093c36008eb236b868a6e52e97a4a6b3dc35ce0a4224689d711bbbd63073653622b06cc745294f53bed7ef18', 
            'debian:aarch64:11'   => '2493497f388797c68154b462660c848067b49d45ef24943d9edac3653a263d6c6129371cc0db07bcfde4bc5533fd45f7a17a792ee4dd4d999872f490962931dd',

            'debian:12' => '12687c75a8cd4dc99d26963be71dd0b922194f64fa31267a40d6aed7b73de02dbf0bd2a006219abdf0021065821308d9106a6b6a4aa44dbe911299bbe9766777',
            'debian:aarch64:12' => 'a9d7ec1cd626c6954e24fd0be0979b909fdd4c203bcee967428bc209877e4aec8b6c6b494bfc12b875b523e4fe70b8f25391939c85b2a61ec2293869112f767b',

            'ubuntu:16.04'        => '2346e76308afeb174d0825921e2e0b417f268745ceef99ce38f148a00f02ca0763256025245aea56ff4f65922ab63ca037857e9b53377c6be972048e94767cb9',
            'ubuntu:18.04'        => '4e6da7f81d195e61c92189e3382021ba9180ca25e91067be91d3fb681d35804bce0fbbe7afc82a0d988a063de29895dbef1ce2c3c3a36458f64219ba7eae5792',
            
            'ubuntu:20.04'        => '08723db3b20b948a8eb2e7e98e548c5030ac44e79b7561e3a9994865eaeec24f48f9904f3d1005e0b7b8818055ffa3d197cc6cd53dbdc7cdca7f1de8f242b245',
            'ubuntu:aarch64:20.04'=> '23001ad8d467e167d2d287acb8ab50551cb18256a3404afffd8d1e247fa2b390203c4328361ea4e1d3e3bf8342bdd71f34bfddbac90b99e8a652ee730ef7d794',

            'ubuntu:22.04'        => '9ba3803665cab932e033721c6be78850453a3db9cfa0b248c1f754f6287d8a6dfe959b6eb967c95b475168d3a4ec41685725a52b8466145b2d9892b79f97283b',
            'ubuntu:aarch64:22.04'=> 'e0742a48ab2b775c0978a698a672fb4bf4a2f94e73be4a38976e68141c5e71b3c6c38734dfcedc405774eb2e3d175b169cefd73873475d6ccfeed582715643e8',
        },
        'zlib_1_2_13'           => {
            'centos:7'            => '649e8353e1c7ad7597378b25a81e3bccda28441a80a40d12a3e5e5bee34b88681e90157118736358e858a964b1bdc8cb1c35c6df3bdc2aeafe31664abcabb93f',
            
            'centos:8'            => 'f4fa12d80f9a56ecf8dd8ed09de98c1204b8755f7426495ab5671d7dd42828dc31a790e0bab2a4a69224bf8bb6a8f1cdd1bf1444e596d58a08345b98e4ce6f89',
            'centos:aarch64:8'    => 'f1f417d99472c8c1b2d56ab706867c3b027078dcb6050741750015ff14827ddba30d73adb9f35c1fa0892125872bbe32d2d30e99874b5d7ef36e1b70107593d1',

            'centos:9'            => 'd0a58e00541a2808db3e701d7f1148e1d68527802a4a63d6b305bf37aca2e39045b28d0527b46d75b9d008c7e8730eddca6c567e8b1d5c7c9381fa71fcaea3ec',
            'centos:aarch64:9'    => '2eea56c656faa4c1e6668644a3ab5793482f4b645a57163697a63a12769113a21c85a71dab747118d498a3658d359b6934d1c7a9dd533f9e782ef6450abbf3af',

            'debian:9'            => 'f2d63bb2b629408166da876a3797fe4b2f71aed793696634b9653248eae0ac5ff50f39e48afb504edf08c99a9e1fe4f6568b4be59e3a2116970dc2e030eb312c',
            'debian:10'           => '8f7d5ae6b8922b0da22c94ad6dac2bde9c30e4902db93666c8dd1e8985c7c658a581a296bd160c5fff9c52c969b95aa806a8ae7dd4ee94eeb165d62a7fa499f8',
            
            'debian:11'           => 'f44a69f274b8bad567b197248587c35dfb1ae0a58f921075d79b0c855df347b796593435f6a0ab6af92fd1464ef0a8032e7f2e8889c7844a38a2a04705bf6f5c', 
            'debian:aarch64:11'   => '1af74cc8d2f7efd29393867475460ead42dad622386ff86cb48b74a8961c5091c3ddcf95968f60f8918f795ab609e24478f1154b6833dbf1fdfa2ed5062266d1',

            'debian:12' => '83d8a2b298fcb154a842888a28fcd0d000218919a4f28c132eb78c6a4b0f7bf10d80995a0079128957359202ed36ab01178b927a1b428bc6cf74b0bd81e81f11',
            'debian:aarch64:12' => '9f6ce5568f71dd26258ca7d9c6a0a3fd05381b9b419486f016e29d50cb93762f13eda5d26103059c868739ff92e67dcc9f013d6afbe8d0fbe01e95ed94986a75',

            'ubuntu:16.04'        => 'e4a3e89bd72bef42a2fdc3a13559966924361593bd03318532cbe81a5f70ef1991f8e5ab245e4740ef97deae75b907b27d9a8c4ed33d2be88ed912a31d0e7b2e',
            'ubuntu:18.04'        => '0bfe299e2d99ad9a163e1e32e1f23f0126237f171a05dcbffbe86e2d76ee770a739794e9148d25b66916ce0531eb2811da682f99b1dc9405ec7c5b88db49dd26',
            
            'ubuntu:20.04'        => 'ad51fa641299a4a72f2c767e0d3c3b754b89482591fb0381a2ebfe6465825b03907203af4384ef85515410ae31be0daf6573c9c381de5a3748ed19ffd56db0e3',
            'ubuntu:aarch64:20.04'=> '918141f90f74f92aa9ec4194a5cea22baefdfaac601401cf9ab382b5f35707c3e9f005a4f05c79b362a1b5216b4d46fbffadda70158391049991c4174cd81a73',

            'ubuntu:22.04'        => '3458922d32fe306526b48400f5f75dc756f04a2edea355c8e2fa9041d7c3577808e575f648eff1dc0f3e8ef88121efd5ed8fdeaf9a9a89de801ae607ce30f624',
            'ubuntu:aarch64:22.04'=> '3e7b7250efd933aa8a58b9560b7e231a3496fc8969bb36a97b748a4ae59c9de296679aa1bbed7bd9fdfce7e97f97340e241afd93f2b6c472569a6c7158101953',
        },
        'cares_1_18_1'          => {
            'centos:7'            => '65902575e20b3297a5a45a6bafcc093a744e4774ea47bb1604c828dfa2eb9a8ccd63cfc4a2bffbb970540ca6f5122235c5e19f10690d898dad341c78a3977383',
            
            'centos:8'            => '6fa9349119489102decadac528b040f9919d6837a00deabb5e661f2c4f41d6c78782b677e83bf73179ccaa59eb1e85066e0bc06313e6bc0013b6f076e03496e8',
            'centos:aarch64:8'    => 'c3942c442173127dfb99f08ba21c699c0abb19108703842452f54b2d8d89cb4a8c636845e8746e4316ca55388386f39f53cbf44ad49cd6cb173461dcae503dc9',

            'centos:9'            => '630f37a4363b42ca2256a3482009f6535680efc504e6df5ac2ea07104331803d14bc610e472b6143127eccb3315bd90a4961c1bbd13e47f2bf6be14000b3427d',
            'centos:aarch64:9'    => 'b5b4ea12176f7db5591c862077f621ecaaced9c276231d81c189c8262b978f68d084e6d6e2b2fcaa488c0c1ae8fad5a9b36a861c91f77569f722f4c413617540',

            'debian:9'            => '1f4474b79ca5f01ff4ee8edc3f25551c7d1425e691a135348a242784eafb21c625af4a189bff3275a667a61f78269f199b70077d7ff9755e8f2a30ad1ba6d200',
            'debian:10'           => '433fdaed84962575809969d36a5587becbcf557221b82dfe4c65c4a67e6736de0dfe1408e1fb8859aacf979931a75483bac7679f210c84a5b030ddeba079524d',
            
            'debian:11'           => 'ac55ef15730576b2e4c464775cfcfd13a67c497787d80719d524992585af9f78271d1a1e80cacb3c7566ee240cddf459cae933621fe8574d906be708fd23a40e', 
            'debian:aarch64:11'   => 'ef28a53a611b3dbcf0f674f85cac52fdc69d897d8d9780caf1767d24b363d88e177972927632508dcd92946f582f506d19aa1e030a4eba05d65cb19d4a414e07',

            'debian:12' => 'abd0c3872dd7b90f853931bb5a50dcb3f84acfecbc04e6796639ed9af240735485e8cc0e0fe2126e857a2f265d73edc4c9a0842afa0964b1522531ee56b7ed2b',
            'debian:aarch64:12' => 'ba1c399fc7310c2b6c5b3775f81ea4c30bd5d43a66f64504920dd53d242641bfe86ab47a8ca093667f40da35fe898225d9dbb9d81a95ea88018fd9932345479d',

            'ubuntu:16.04'        => '8ad5c1e5cdc36b609d163cde39f87d99fb8281baf5c692f5525c3234dc8788f8f50f400cb4e2ca0e089c19275167d20e634f509d06c4d61a827ea2e4d3719dde',
            'ubuntu:18.04'        => '58fdfadf9492cba13e907f2227d3ed249de78e8839ecfecc01957d3e62c8b4c5969ac647068ee87e84a44ee853fa88367ba29fd8dab6e53a685f31e699148ee0',
            
            'ubuntu:20.04'        => '590469366f085d5e996e6d5c6bf1eaa27c0b209c16fab7ba7bbec71dec44cf4522e1997a72bd48daee694b6bddb0415ded4b3ebf4921dc903eab5fab0997feab',
            'ubuntu:aarch64:20.04'=> '88d8f14e0995e017315801fc18b2d8b0ac9bdfce88889b715e13c7d61440cc0eda0faa4f407997248c1c00110ab213e82c88e9fa27de58aa55fc977b0f06b71f',

            'ubuntu:22.04'        => '4447ff5648ddf7b96365be52505f585eb1d51f1c8ab2383553073239df538a5e5cbfdac04cf7998d0ef71bd1f201113bafe52d052dcc57b123132aa3f7011ab8',
            'ubuntu:aarch64:22.04'=> '957d26b5370f40b0873d3d0b273496688df8130a7e4568db57171e418e59dd27685cc81922c89b890b817269725f0ff49cc9511fb77203df3a32e51f6891f79a',
        },
        'protobuf_21_12'        => {
            'centos:7'            => '82ad83b8532cf234f9bbc6660c77a893279f8ff27c38b14484db3063a65ca15b3dd427573daf915ef2097137640fa9ff859761e6d0696978f9c120cd31099564',
            
            'centos:8'            => 'd0819b908a3deccab82aefdc50316717eb0118666c919b23638d2675b1e410f30ef110f3c687b7df709b05121e88aa9dd1a6a06ed675d29544f40cf8669bb7a8',
            'centos:aarch64:8'    => '898f6e67734dbd0bdb4a89f2ed10330d45f961edbb527dc67f424e886162b80316e58b64d66c5f381c64f46f1f49c550fbb5f50fe620143a86b5d9b172ae44b6',

            'centos:9'            => '2ece586671958cf8d619f6da6b6102e1ae36ffc15113d0fe9c3b151a6b15bffbf2ae957c4b74bfcf85996b6327cddf120bc1951b68376bc5d72c5609f9b63b9b',
            'centos:aarch64:9'    => 'f90e7d3f23457cc13ea19559aca093ab58692ac81f233bed355f4a0cd9c7c8aa1ac44c5e336b39d807a2f46386368a6e9617728479b9007aef3fdacf1a7510b3',

            'debian:9'            => '77882d112364681cfe795a8676d75d214a1030f0bf1a2e281b4100b493b8b4eb6e3c57db9f19770f6df9c3d629a43aebba446391bff299170f9ed9ee08cd0f52',
            'debian:10'           => 'b0dde2a94dc7e935f906608be5c8204393e87ba5703b78b84ad41ab690107eb306c50c9572669b0d18a55334ba26ed22a2242b54d6e30dffb1c11f8328b23c20',
            
            'debian:11'           => '97252bc39c9c218f02f1c5d1020296497934b1fb2ed9300c133db650ef327cbb06e5fb985234bc00ca9e86239ff2dd28b844a0eb92dedad2d4a3d88e47984caf', 
            'debian:aarch64:11'   => '275d64600136495ec93288b0a3f70d4447dcfa0f4a92c0e42aa5930acfc8ef86dc114177f7a6f0e1bb939eea9cdc4bc8faf97197e9b9ab447097d49dfd441240',

            'debian:12' => '8bfe22a6dec32bc56b2c042424930c18b397696fb8d67001ef38f93e1b7892fdfc947f1be1d697c9ddd245b56e029080535d385a663dc61c1f6bf959558e28c0',
            'debian:aarch64:12' => '144a7b6bf0fa8a6da23f05465e8d32ff1c53b33c8db092cc4457a2a8c70355f6fd8a630831ba0aa87f3d04b2624263de302bb7a95fe272ce57866f45ac329d6b',

            'ubuntu:16.04'        => '3bc1b533b0e67b1c3599a63510a9a95b170029ff74cff5d1960028b770631c5b14bab38e39ab0aaa4c9a5e8bdc295b671dbca2aded7e5fedc99179f8b1a0f83e',
            'ubuntu:18.04'        => '77ea38ecab665863631b2882338a7668e730d870f02377c4ceb10af1a3f91d35befd110790866ec8da6e9cd9e2cb4b88a078487b668d397b624cf5e9e2bd9282',
            
            'ubuntu:20.04'        => '3f4bccf529d54bb3dbffe3dfe7ff95a2f1232ac102b69c7034fa7b3254bd99ba7fd3bddf5679678e2365c0fdb96251021fba38da556fa62735743a17b8eb0b9e',
            'ubuntu:aarch64:20.04'=> '59469a1d99b30eb5472d3d595180319213e4ae3c16a209d719a65cba2176f5e398add6559d4a3a34f033477c268e8b96fa19ae3c45b7349f4d7e10787abbc040',

            'ubuntu:22.04'        => '5a8b91f98531d91fc5836ca63246016ee1be0dfc50b51cbf2cb6e8c5f84c3716ce6700aa7d30b33c986407a25dc8e39aa6e8628fce85f1947de49edb3ba5c211',
            'ubuntu:aarch64:22.04'=> '4ccf53133017195dfcb16da67912ea15ff6c8d2aa8530d808f971f6854fe562a88a46bbc4fb99965add5f3054d2f5fc24f4032feca5b6124cae4807a3c8923a2',
        },
        'grpc_1_49_2'           => {
            'centos:7'            => '4c77cf97c5c42dfddf002b9b453459ed28c8de3715145c8f162fed45f650400bcdf5c7fc714aa50b1fa14f486ae86b47d6d2cb03d00862281dda4482583385db',
            
            'centos:8'            => '02ccf070291c2cb1268cf3887c8e92c99ac614a757cafdf96c7235c5a2e583be5a89f8174d5fed93f3dabc17f9049a90064b9b88f465e3c1736dcf3f2505e2a3',
            'centos:aarch64:8'    => '9957c8c8e66a82c245346dbfc0edb5fbee36ddf3dada7315d0529d9a2b7ac838dd173f1cfea6af1986a89aba5273d676477ff5b3c65e422c5e95daffe317f137',

            'centos:9'            => '0848adea41083de22470fde9ce161ca4adf005a6931095b99ad5844808c7ee09f1d5139e9c78e8b4ff5032e06a73ca0d0428f1503838eec46748625e54acf94f',
            'centos:aarch64:9'    => '451f94967baa95bfa7826ebc3fc8d1deae544bff90b6a37486b5af03155d315e9c3bcc99f0a71deda8d380cf41a5f644ee0d227c8dddccfb182bfebce4656b01',

            'debian:9'            => 'eaa6052481b1ef2535bd474caf404763a1b7b3eb85ba3ae5c0d1effee7ceb86577689e57666fbbb10bb100351ecd61e966cb72ff1ef376fdfb1ebbcb48ff1870',
            'debian:10'           => '71c6d626aaebcec2f9faa8df215ac988379ef3b7eeb2bdbef4d176d6a3534ec561fa55a4f2b69979c9cd51dcd52aa59b937718066f35cfb1cef5861f2e988bf8',
            
            'debian:11'           => 'bd54409a859c088e60363d5cc5afc03d2326759ba0c40e1d08a83518b0556c953830fe232945252174e69482520eec3f6f7999b85eaa417ac780dce1bd064a70', 
            'debian:aarch64:11'   => '9d7b42ecc1f230436e069d321e64186483939a3aa61173d3da39fc92723d363115a5e19e7276492dfefacc091dab53edf32eab34028da16110ef8caa80bf0057',

            'debian:12' => 'd83a08f2f932a232b26dd270e861e769c4007deed7fb052d19491dfcd186ebfe9218388ac89bb6d18ca333e347992302c2fddcb41b7d3d0c246c60340aa48a14',
            'debian:aarch64:12' => '5baf57563663044e8893acd787f4e324624eebbcd76dc828f91f6655a3ff4bcebbf62ad5a7bb521b4b4e52c940067c8f4f116995b4754af537510b5964442fd2',

            'ubuntu:16.04'        => '4c26236d708260d682f346eb5fb9c4c3828cd31c286f4ae95357e9e4b9a99220e29d65e7cb5ea25dd9210bc08194170863b275f0016bce8302e6d2e8a31687e2',
            'ubuntu:18.04'        => 'b885b3e7b22a1ec0d4a49d7de952a1c667eab4313c6c1e299f05969bfb194aa677bcce5cf495230087b65e25f76496786f998fdb250fd7c7826ba98164434aa1',
            
            'ubuntu:20.04'        => 'af2a70d0ca5e77ebac80c2168a2b3627e40a2bfb1d79e63fd6fb2708d6f4db9dc2a24ef467615a0ef49f57b6444e4ddc8db4811ca4700e43b9b04c7b9dbb70a7',
            'ubuntu:aarch64:20.04'=> 'b827a503307d981ec28e797f856c033349f6e1a75dd507cd6f1ff0a309db9082a81b11690a0db84d0b162f7d743f138c68bd790f0af04d49a27604216db3ab9f',

            'ubuntu:22.04'        => '32e28500c2ad633a7780ae514383bdaf91766db0a50c5fbba5079869beedbf1d2fb4c8fe67b05aea7ae9460a7269dde2adc54f1e4c1a6b393ffa84d49a26c885',
            'ubuntu:aarch64:22.04'=> '10ed552dcc8b414e17ef6950c47a75e75ffc1511bc082ebc11a6bcaf07789a8425ec65136a8ae6c9920af60b9e195bd9dd7ff252610bcfdc236dc3021d1b22a5',
        },
        'elfutils_0_186'        => {
            'centos:7'            => '23acf9d80f72da864310f13b36b941938a841c6418c5378f6c3620a339d0f018376e52509216417ec9c0ce3d65c9a285d2c009ec5245e3ee01e9e54d2f10b2f8',
            
            'centos:8'            => '28ffbc485b5feaa3ba334d34757a9f39e2d99c97f00ca4163e2d8ce24746bf5619338c279c873ab2d28fd7156b556816ee7cc2833a12c4391f65dddfc8392a00',
            'centos:aarch64:8'    => '4e6929ad6e11cc9554fc4a4aba5fe336d01b4e4a4d99f12bedeb3ca0aee021e5d59ae05b0ed184ba1f58be8c9a3e48d9422d076e048a8ef3ab70a2080e00688d',

            'centos:9'            => 'b518006d054e123142c186b7eeff5f0d76ea3828487da6cab46e1ad172367a92dc038b1b88dd284226909df25bec3979e400637336839a4d322cac376afda8ec',
            'centos:aarch64:9'    => '60e416ad017664e90f8fcb6662d4e1f1d1aedc12278918ef5236ab5900926ea68d6f8f1a3ef46b6c1aba21483cbe9d9f1ab1332ddffe499ed0811cc12a947b4b',

            'debian:9'            => 'd5cc79509a537feb7fe2cc0241695f530ac5459f7dbdc83d16590db83057cc3ee79f2197033d9ce6a8530cc5491836943a04e18af13a2c71d40f6b68a3ebfd6d',
            'debian:10'           => '16bdd1aa0feee95d529fa98bf2db5a5b3a834883ba4b890773d32fc3a7c5b04a9a5212d2b6d9d7aa5d9a0176a9e9002743d20515912381dcafbadc766f8d0a9d',
            
            'debian:11'           => 'b9adf5fde5078835cd7ba9f17cfc770849bf3e6255f9f6c6686dba85472b92ff5b75b69b9db8f6d8707fcb3c819af2089ef595973410124d822d62eb47381052', 
            'debian:aarch64:11'   => '06a380b936d34265024031fe0daaf4aca88f9f6ad7a35f727ab68fb4eecb22d96287cfc0713d57bfcf0051524ab06477197594bba4f3b39e3d3030834be8b12c',

            'debian:12' => '276deea5a2f071d1a9920fe1554233409dba97c7975d9f33f1425d567f5f6ccae1b102b27cddf538750260e459e42e41938c62164aa0a804c065edfa9e50c60d',
            'debian:aarch64:12' => '9472ed980f2a2fe52ce93f31aa7b08b9b60a1650eefce042c0b73e7236c9f54eabd902ea6d94a9153feea6630b4d2dbbd49c11dc4d584ddbdaaa169ad33a4c52',

            'ubuntu:16.04'        => 'ad8aec36dedc00aeebea0b3a5e10a8cea06d94db5bdea37883d8040e6c5e17287c78413f1de37067164c919fe47c57d5907a3a2de7602ea047bf819425ce4f47',
            'ubuntu:18.04'        => 'bc29397fab79440a6677844dcdd550e6a157cf4c4e779c9aca5a9d38e2d8ab1e5527585e16bebf4deca765fe9afde2c1ebc1f677d2444b9b48e6bf9a2b97288d',
            
            'ubuntu:20.04'        => '81a076a04725e8ef7269bd5c381619b0b18ca866639f064088c80ee12ca2d5f8e26d913723fd5f3ca609aca4cd21540f51e67b16a5728fd2dffa151e8b61aa57',
            'ubuntu:aarch64:20.04'=> '2bea405f717de94b105494c5a2cfbd37b3ef8e9ab6902ecbebbae2242fb1fca1fc255f68d967b2fb21ef66b358830ef4d6c30d2b510fcf0a1972a6618f75e806',

            'ubuntu:22.04'        => 'f714682aa3bb7a8a86880973eea1461baf2d00fd6cd8d67a5e0c287079bc36da0cd7b196501e4cad708665b713d7e97452b03e1c33db58dc3ed6a05c2893b32e',
            'ubuntu:aarch64:22.04'=> '5a408486dbe7c4f84e7f4f528e0bcbf396dc4f256f78f8a6a1604e1837e08939e5d6d11d3aa440ae9623f6a3715898744791ca6f147f533f47fb115286b3398d',
        },
        'bpf_1_0_1'             => {
            'centos:7'            => 'b6c6b072cef81b2462c280935852f085b7e09f9677723caf9bb5df08971886985446ba20a4aa984381c766ed0fc2d2b9cd2afaa7ab3d63becde566738058fd1d',

            'centos:8'            => '70787f1c28791e01ed1612df7bce226bd7e293f3b17ecfa22284841198a050c0422e46dc78597226c091e04198b8b0681cd1d4d5fde4f068434c45876b1dad72',
            'centos:aarch64:8'    => '2682ecd75542212b8e23d63cc057b9a9ee944cd991eb20a41ae25bbc61828de440cae5927a6f34e31182a642854b91709146781b7a68cf52ae9f952b0b358e38',

            'centos:9'            => '6313c8ad1c6e6e070e06796807770a291d85ae6e5fb67d3045dbcb144016968e34b5256f83006be0847fcc53222b931c300b11598d7bf031d75c6284343a6db1',
            'centos:aarch64:9'    => '373d469eb4c8281c1632c345681d5bccf58fa65c23620239df651ac669b8c2abdeb926e7304fea513881cab07eecb3815a161220e671ee5ac77b2aa36803b0a6',

            'debian:9'            => '0f397e08a6bec515260c2937d76dbf48ad8b3452ead4ac5c41d4b3536ba7e8a40fa703f7638111492e690d9c9e3fd5316aaf41c9c93e82eacd8dd0fb6bac2c2c',
            'debian:10'           => '8f2e456bcd0b89fafe97c6368f725d85230f183f72a720bb4f7da043ca6ea255a2c97e374eb78407e8ef969d84faebd63cf5b509eb9bf4476fac5b08567574b9',

            'debian:11'           => '11e91e87b2d10d5e73958c1944abb50e1c9df5891ad563683e2b313848c85d3fd15aff8ce70445afc768dd490c5d8de12f887b314eb55af7e4a8f9613c003806',
            'debian:aarch64:11'   => 'a187bea689bbccca48ca5cbc0fda015251713db55215e6bbeade1e96f93b6391597928dda66ff91cceee254dcea7fabaa42c05336a900260bd23503b0f385f2d',

            'debian:12' => 'c1023d1208a6a8a43afa143df13bf3e83384c56270ce1869d5f37afe8445edba239792c76ea9b731c24cd622089ae89cd053a499ac3d57983902295e2b963985',
            'debian:aarch64:12' => '546fd47f77992ca4c63b27e37e1143a6d1b6d532ee39d9bfa2db9814eba786626eecca8b6439e2ada0041b82817f9b0a88ef5c87576d3d19519d1f69771b28d1',

            'ubuntu:16.04'        => '548a80ace21320b6ecd170868852dfa1ade66c23a5c8fb4879ca911132a2ef3bcce51e622786e69ee0b60ddd883a15e1fbf65b6b03d36c27219dc20e824a8eb7',
            'ubuntu:18.04'        => 'bac4d836afc9b24d3939951f8a48a3077a1ebfe1a3523a4080fa07cda6a2bc5b48334452b4f9b120ecd17936203820c093f8ed3e900d17e23675ac686241f823',

            'ubuntu:20.04'        => '823cf47a6af9473ab640335a80da075be1db40fd27e3aaef84fffd36280c1b7982640795d09e541599473177e203d6cc21615d87d8f0e2b556ca8268cc3ca4d6',
            'ubuntu:aarch64:20.04'=> 'c7947b81d4894ed47d73f10ace9cc08cad0c668995151d6e95cf93f8a7ffb9e940e77c65deb423902b8ead7e7aa3144d14bf7230068ba34c87b27dd7c7e76bef',

            'ubuntu:22.04'        => 'c92b722e28624633de4e8411f89984434d4281d4e674677b800317235f5363285c5618e93a59945b90196026b0c4d061716c7e5bde817e4f4bb93efbaaeefb12',
            'ubuntu:aarch64:22.04'=> '5899eb3741c29a7c7d1e6f8a60fa08813890a60b45e5f7d0f980e74287ad48953d897263b8d3455116ac058db26e424576e1046f9c35d0c9262cd31b0ff0e4ae',
        },
        'rdkafka_1_7_0'           => {
            'centos:7'            => '40e01992e97b4620eb6c86def5efb69734534cf24a374f74ba9a1f640303f08a413bf5c3d2bed447bd1afee082b0bf213d4d3da9dfe696ecf3226a2058098725',
            
            'centos:8'            => '6a733ea0a86c042071cc524a6810483ccafa9a254a1f091288e862f239e95f835c727c190f5d6a9098bf0a9253c979e14012a05cfacd3df0197d1c99c232dcd2',
            'centos:aarch64:8'    => '2dfc6ea5cca47649af47a781546ba2113bce5d6025efc9f6254a2970dfbef0aced3fb76bd53ac5f5dc1ba5fe47a40af9fdd25d8bf8ad5eec95c099b27d384921',

            'centos:9'            => '544d070e5e61e8d12bab9be9c39d040d7380308241f81f0676ddb627764066788b4a4a45693b8d656d2ed2e412501cedb797b94cea1169d18045ac541d51bf82',
            'centos:aarch64:9'    => '8c3e3abd7428359fb3085b62b9f4f8683df2bd486ca67095f2e05ef474522cd8a87fbbe7e5b448b46b197a80f4c0b611fc346ae386b934e1b3597263f92cb793',

            'debian:9'            => '67981b5f576971a79e4685bf867dbc7685453842a31b48a6d48a82f639d67f4be6f7fb1ea8ae60f6170c6367874c05362fb05e4114397016ef7c6fdd6eb6e387',
            'debian:10'           => '6abed5425d55ebe0c251e9b4e51750297491d7fe15c4e1584c53f38d660d0ae91cf05565c9db5cfa36d217becf32ed64a099b7af55391da299536689083cf6d4',
            
            'debian:11'           => '2f94bfa0602b780a4f6685d4f1b56ae1276f9e6688bdab380b6e91b90f9f83330f94eccc84d95171399f6c980c2eefd72a587f0d483ecd159cbe9d23bd9084b0', 
            'debian:aarch64:11'   => 'f46ef8109d0d606e43b862b82dab27c623490cb12182a0b67749b267a814e6febb36ae54f9fdf352e5041d4082f013ec1c556fbac023fc5f943462b2332d3a73',

            'debian:12' => 'b7f12a4b78e974e078579e2e2d52a05a82bc1457bfeadf4617343a01cf6a5e0e8e5bf3c12114d4554407228eab3f1fb494843b0b438e6293b03df99bb1c409b1',
            'debian:aarch64:12' => 'c19127218e44c903e7059ef7d78204244ad05fa76930e3a9d22223750e361198b6fbb05f3b6a992a16b4b225620a2035cddd8cef50c1c926b564d8f4d9fd3edd',

            'ubuntu:16.04'        => 'cf2610a5064f3149398c6381b595f746dc489da249376db66658dc48d769b0a4f0526edc70130736899db213663b20073705f121c773b92e6bc0a79f46b701cb',
            'ubuntu:18.04'        => '5c39654d637d8badd9cf3a0c60d2e84dbf84378d3ef57e20db8f86f018759fdacf256a886fe1fc05e8fa34bb4495593c3e80c2cd8f79933c7e653e60c5a03dfe',
            
            'ubuntu:20.04'        => 'cdb12d94f906322be7bdd2ea91b54c375656d0ae8b617be11c236e5f195fa08f3324596a8a85bd09736192b795b05b626b1228a51c82279c29d330705d0a25bb',
            'ubuntu:aarch64:20.04'=> '09c948a852cff381738106746c4fd0951a3def933a32480a2289439e8afa582b3afd273baa69f7e0555acc0ab3d428d9425a44207322a67ac5215651d03d5c0a',

            'ubuntu:22.04'        => 'c547ecc1e5d94f557184fe7a9202a56065edc5afcb71d8b803be7d864c20422af889a7ed693623280ee0a0991cabde99901edfa5ed02a352d9bd63f716277f42',
            'ubuntu:aarch64:22.04'=> 'c51ac309888e879d303f4aefaaeba1d86c1e2159a77dc9f0c8e8e0638c1a80f133f32b197cd4aca7e7ca49142ad7e96d964542444de94817eeb2bb608c8e348c',
        },
        'cppkafka_0_3_1'          => {
            'centos:7'            => '47fc81102062f418a0895f2787bf337da8d7e766b178ed315284cc12913c58b99e395ad044e2e5954299c3c9cde23b3145dc43d4469d360aee66cc850b09b82e',
            
            'centos:8'            => '206b85a820f9c7f7cf4d9c2da600df0a7997706f25b356d355121136fac524eeecc2ff3bc625f796693a47af8ccbc4fc7cb8f3d23f656ee70c7ccf57e8308922',
            'centos:aarch64:8'    => '5f2eb5af9579d4bbd6439f9359e9139a2d33ada050b7aa12e01a187594cf07c58da20c969cf53a594a58a6dcfe333644439e60f138861905546bce81a4f87f4e',

            'centos:9'            => '1b22492da81139d4f42640b43c43f2e3ca43dc51b6cb2136a80297ba20ecd28f0cfcc035f11526d1b42975558547f978bba01b418c5d9bc0d3f1e910bde5a8ca',
            'centos:aarch64:9'    => '236a613dae16f5ecd48144fe0fb5265ffa9b3d9b53edf944c60a6b0ebfc16f7318d17794a3a39f8ede4b2da4a82ae8e9627ab667967d682d8057076e6526fef2',

            'debian:9'            => '6d9abff6ea377ef058f48663c40a54142c19cc43a69d67766dedfd1ddcb4c02c5b9a7c62b8122dc8692d5bc0655857f53d006f8d32a37004e4967368180c073c',
            'debian:10'           => 'c6316b9171b31eb94b2c31b9532d38f7db372ede62c06372b473149f3e4a2ba386439f4e5caaa7582f0ea015460903d4cd3f750b0f57fa5fc25612a50c10b501',
            
            'debian:11'           => 'ff83197e4d9056e629fe8633cb605ae8d5957b585f450f190ea01644ff850fa4bf69bccef15d15848896a35a49b3c38918261abe1bb6fc28991369666087ba38',
            'debian:aarch64:11'   => 'fd964a064e88d4f2038539eae8f419095744e9764c22fb0c9722d2b358116a261e5f6ccd277a2fd377c05b8a7dad727635aa972502b9c84fb7d887d9923fde5f',

            'debian:12' => 'eeda4bc9d1a9ca87ddad988fba0999a66c473df7a0eb48c1f18cbdd3995a957d543d68c20b1ff8bfb8deac60dcbb4c47a6a71834f7131abb853ba6bb4c201eb3',
            'debian:aarch64:12' => 'b6f5ee512a64f4fb7736f3657ffba8e5d36f304cceb8e4546ecc9202f1144a6f6db3833a841690d88ef60f1bb574bd91ac7db984f6f34a7097b5108857294e36',

            'ubuntu:16.04'        => '5025577664c889efb047235c05a38f083bd066da7a2d8261ea2357ff9b677b813e5cf11de7ed1f46e9df3fd846c54d977880f1375b44a6bd5b74990c34b36f51',
            'ubuntu:18.04'        => '216b21370fbf246c8b2b5f99c31b4d09935339e5d4e2cf529621394df1fbf5cf99cf859f2c29813e05c6f0e9c29c1c154d98676cc125e010ca8b45f3941b1337',
            
            'ubuntu:20.04'        => '8394ab12a08626c886e5d3aee676e2abc46aa408def8405759e840d2ed8fe7e6fd215ed79dd6e57c42213f3cf199f58cbbd8752286e3449a2e17e78865719278',
            'ubuntu:aarch64:20.04'=> '2962a2fe17515ed254db3bb616d2255f568b9678931ede0c121245bf126ec97082bbd793207ea15ccf34e1c56bd350209ba68a0940ab8e526c435fb979ce79af',

            'ubuntu:22.04'        => '9da7b3c41adc768bbfa84d82f6edca9e5c37423c9c04766e992d0473ed5bc08817be01c35dddde33ebcfc9032bfd2ea69657b259161649c23ed64ea22ce95291', 
            'ubuntu:aarch64:22.04'=> 'fda755c2fcfe73cd09c5cdb1666b7d1a33562cf920ef8b87f70e693de8b0c86b8705b9bd9313bcde4122126feda65c5d15e25db43e68f5a23de9b628025035d0',
        },
        'gobgp_3_12_0'          => {
            'centos:7'            => 'ee4e8a976a16b4f0e49753a81e17405b3c219d979313a39e059ec99125e7a5804691c30f2989e60b404d6a9cdc5636d6d9e545e6766c3fd4bede4ff0b830f204',

            'centos:8'            => 'ca142c7a76f17e4f69ef7c14df0751425656faff8ae1309895ff295950e6fc82ecc497e060f437a45e3e8689f0c561d102f5cb8f920928d2b3ecc91430011a22',
            'centos:aarch64:8'    => 'f701bbf7739299706799afe0f8dcf1cf9f6c6bbb2046f445b4c7b3498dacfaa3de456e7f960c3a2b07580005dc78f1b273e0c0595e8ec1c37a3f96301cb71acb',

            'centos:9'            => '25c504c671be26066c1f370eb03bb681209c87bba0c6fce766c8416534007af8e8279b360072711326fa1d248255201adf06c0ccbd1682ab34860d21f72c190f',
            'centos:aarch64:9'    => 'cdd4c9a1a0e25f584a1f33ba159c34d7a8b7d3c285a75a2ad0675aebe94aba888726463eafb37cb4f96751be4a474e4b95603c15c7bef0219586bcc94767263a',

            'debian:9'            => '72305f540d838fb5c7e0b416e5c8a493033da4d9afe21ab979d619a1df69115b9036f824aff8d78145aa9742efe4e5363756b87082de6de13dfb17b856a54762',
            'debian:10'           => '10a38076bebd3a1eb6dd81c5374f209f17808e51ac6476dc256d2a91cd904d5b15a6f9a2161099b2d1e6eaaecc1c3beb54cca1083ac11900001374f4624b38f3',

            'debian:11'           => '750102bac73ec2c1fb36f470c86d37a2ae59bd49cf76e1ea48385099d6a3bad0bc49768ee3b41ba2f85de7131e28f757d6093c6be879165e211615d50d69239a',
            'debian:aarch64:11'   => '5569b4bac0ccfd3a372475fc03d1a4ea6eda37b0c28b8e0854b831115396b4d5618c6ccca50271691f800ece304983c2e8022e9e507f1fa0dad568d320431c61',

            'debian:12' => '0aabe505b4ea6649043203a9f4d28dc27efb6fdef8c61bd0c21f0696dabba697a8f7568ce8455a90fb50dde87a30572e8760c66a5d90e647bc0facbe7d9ed2fa',
            'debian:aarch64:12' => '6a857eb5136626ae2ebb7c5bfb5204172328e9a841a193b0c1f76a87a72472c0f8062f386af49ab3acd59ccf7735e0b247489e15af498dd734bcd66963509d3d',

            'ubuntu:16.04'        => 'ca142c7a76f17e4f69ef7c14df0751425656faff8ae1309895ff295950e6fc82ecc497e060f437a45e3e8689f0c561d102f5cb8f920928d2b3ecc91430011a22',
            'ubuntu:18.04'        => '55a829e69aebe296ea1537117150982003f0a647674bfb5b4eafd298db9dc9ea6aa961642693d5e21ca737e735167cfe3ca84780144e842a9946134a99c1f4f3',

            'ubuntu:20.04'        => '750102bac73ec2c1fb36f470c86d37a2ae59bd49cf76e1ea48385099d6a3bad0bc49768ee3b41ba2f85de7131e28f757d6093c6be879165e211615d50d69239a',
            'ubuntu:aarch64:20.04'=> '59dbd865794eae5302b908d82c5b89c3dbbd95a9fc47b78bf5e16fd1f9fe34aab03d4294d90ef3000b2aa24039bcc1c939da6c5223ef6f8011370f2024a5d22f',

            'ubuntu:22.04'        => 'b3f2168c6b705804155ca944a6c7850057d50652efc57c3c4194838b147176779b98d7b2bf9af72ee141805d62f7a6c1460244ce60b570dbdffc114d5e7dc899',
            'ubuntu:aarch64:22.04'=> '4e9114ed4c9fde74517f04fc8b79b44854ee5fc8b51b99816ad60dccbc61a682993c4321a0df6920a40164281ba24d171f9d4972e54a9f3015d993caf7d03c47',
        },
        # It's actually 1_1_4rc3 but we use only minor and major numbers
        'log4cpp_1_1_4'         => {
            'centos:7'            => 'daa469b116ecf20004163b5e222840e10bf1c52e92dd28eff6839d3366e260ee63ddddea1e3ce95034243968e52b28c879e508fd05536746010d834b63cf9346',

            'centos:8'            => '8c46f8c02835732ded30b075dc90de0ccbd1fb7ee9b68788791f41638c0ec5fca80ed10ad8f447db7cbcf3a64e9d04bd2178a2a33319909e3a115862fbd63a91',
            'centos:aarch64:8'    => 'ac080e1a74f46063d780d4355445851d41604ffc43cbc275cc0194fc327989d2cbd8e8888156768f46016ab898f72bce27cd29bd53b8350b49e72048f97b6dde',

            'centos:9'            => '010c54e0b62aeda78509bb404e372e85e42073b08b2d0ba90f7e7fcd8bb3d6b943acb56e9dcd8113b44bc6b3bbaa83572cbdf81a9dd7e5b555c29fc73ff46ebf',
            'centos:aarch64:9'    => 'f7d2fad8ac0bb8b7890e9c21fe4b178ee7cefd252484546c91f2c8d21eac6673addfd59323c2623abc1a5d0bb641b807f42153c782a84f1bc593547b9509515b',

            'debian:9'            => 'de75b1f0397338c3167ed65d9bd36f346aaa9ebde4b4cc09cee434b7c34a0ded41263533a3ca2c13201a1418ad0cac804aa9aba18ccb800555123b9f8818d042',
            'debian:10'           => '5567b2a040d71e5c1c44687dd9ed32d3987590e0aae3b5653add8b7885b9e1688ecdbecd23d5c54a309388fcaf234df24464550f662a3f76b3a8a235d93219e9',

            'debian:11'           => 'efd6883dadd7ffc01464d22fc2380edf8b0356ee897a3a3cb901008ef477f9e7769f63bcf66910b3db680dd2f58cb554228454d7c41c30f8782aabc396625d3c',
            'debian:aarch64:11'   => 'e8be2f9eb59364726062047eaaa869ee5e2d0fedf29e1039916360e9f582a9bc82fe3e6b21f5087ea20531ea5b3d79e26a901442fb85cc1c49a5c52d20805bf4',

            'debian:12' => '4411c5d9790806e9b84b002d1cb0115629fba1cb2974ec673e94faeb6121c336c7598961744ca2c15ac4b230e9ba3b5917090e48382d4d89cf9c457a72891867',
            'debian:aarch64:12' => '88f8d935be3a4141d331305621accab0314f09e1b285bd7af3a2ef1a16646e2733716803600d52c042ca2c458a0531b69dd592bd04d2bbfcac5111fdfbec9fef',

            'ubuntu:16.04'        => 'a13743d266a110f3bda44f36c80b62e92c3bf0408b5384488c61a0d42ad2e62212eb39906b33b872afdc567e72ed7b1cc94604dd6dd2c91841a73e6967d6d13e',
            'ubuntu:18.04'        => '6d5a137f839aefaaacff43301d35351b74417e2d45dfdde705c2fc6433aa8bce939be7b727e8b02f83eb19bd4b53b0482630c9035af15856c0738335041b7e0f',

            'ubuntu:20.04'        => 'c2177531121f08279e417489f01b6867c394e4f65d27a6e3928e7377b48adfbbb50bed28eaa17afc230752720d09cb9261df25d9756aac4919923e9599f10e0c',
            'ubuntu:aarch64:20.04'=> '04e2d04e213fca3002b3b943af76a3d32fb150508ec06030843ffd64ec11617c18228f774cf1e9c60bfc9d5d449ec0ef8546abb86154008970ff1ec1fb9fedad',

            'ubuntu:22.04'        => '086e182a2ca2475d46e4a959398d52434d5ad700f2db5a568a5c77b6e91bc51fc34cd36aca7be68810ff0981d304d444bcbb5bc2fa549f8ae3f6d24d8a91157c',
            'ubuntu:aarch64:22.04'=> '82b6229a5346d3859f3263c5a3fae403f7123b2db805e7ef8ca94d3222a5aa8d8ce79a2f6e3345a2849bb949aeb984010154e2119dc20adb5e7052271439492d',
        },
        'gtest_1_13_0' => {
            'debian:9'            => '775fbc33cd00f4d56991d860f38af9360169471e1e45ae87f75aae146d2723338cb51e3c9c99716b5f0e03bad3d9eb20b39d84beaaf8753844cc56c3f503b789',
            'debian:10'           => 'f8759bd2a908e533f56b8401464189f75938ed8ccd23b5de36f5dc5ec408d7c790cef1d594bbeb2e52b8fc526f8267fea296b7e6d159dc8f2b5c4aa7618daf5a',
            
            'debian:11'           => 'ff6e7e6c6922a821173e8ce74340488877c39b9fac35d2f0d6137ed80cbfc423669ff12dd55427553011b700b3a48c970543198748d8fd145d8aa11b62b250ce',
            'debian:aarch64:11'   => 'c30f0962f2ad957b51301ac4132e1b5a2460415bd79440159775a28cf6d0c6fc9a70bef335783ca4bfe3f6ca1c2b60d9d4b0b5be978e5e797127d3dcf91a9a3b',

            'debian:12' => '84825a13b6ee3523e7197f71cc45e709cecdafe02be7fcec1e54cc5551023225603c48e1cddc7c3bd3984efbd6c99559f40310732f8390b79f72973e5a5861a2',
            'debian:aarch64:12' => 'd840ea5cbcca6cd238b133df17457de2f8d6b21e3903c259b1cdf65cc84cd86fe9a8c062c1b09c43b0fbfb377f8f64ba0220f9740e626ce3b03a16a026ce9ec6',

            'ubuntu:16.04'        => '25ea67115d12bb5a647cc762c4c84e63736f0987fe9f07cf84664127a31f93ffe782bec6dd1b9eeffdae27aa13fe2650af6766797baf2d51c8ec2f445cbb637a',
            'ubuntu:18.04'        => 'eccc30f8817656ee5baac9d7ea5502c0461aa2958f61c662b4e55d10f322a0162ef2ed2a0190478ae51650b345714636f612de2fb6a2c243ef8e2a372782958c',

            'ubuntu:20.04'        => 'dd2dae6998f75b88c7b0318737dd9fc1a6f7d59834f0339100a45592cf1fe3056c86e30dcf349a12ca0ec1b0f23fb36d26c856d5ff7b7bd624f3dcf36ff00bfc',
            'ubuntu:aarch64:20.04'=> 'ed97bd06868835ba3e389cd9ca0ccab17df3f5099aab7f8a37eefeed03f65c5468be5cbb4489fe790ee95968a84200fb1c51b5d0225396e2ab27e7372bfb0356',

            'ubuntu:22.04'        => 'adbf6361f608a5dc08f9daef9575b8fedbec8808a3e82c6e8aee4f51325209b067a2e471ad3476da36c4ebefecb5b24457f005626ab48e569f3c2239a509acfb',
            'ubuntu:aarch64:22.04'=> '76e22f295aabbe2d735fcaf753c7648973fc149dc87a3db029728e6a769a4ad82a6c92783e213efffe27ed1f4939b2098bb359ba366b76fa1e994bb80dc60d36',

            'centos:7'            => 'de48a8b8a7403f95bac0abb18d166a48f9c1e60f2b899f1153f177eb89372b8d05ed336856a93abaf6a891b9d8b374470555d04ca3bada7b7032e44d05628c2a',

            'centos:8'            => '85f4f5529d72f66722658fd7e8240857b3439ebf9066eb87dab612400e9e9b7d3209e56db7cfa5d3ac64f28e75ba19bbacbf9f433e561073d41a22f40ce65b87',
            'centos:aarch64:8'    => 'f4b5873c602495ad85ab16ba531ea19c3ca925d5cf9ee62b5a2eccc0b6d85523b0645b04717e1073ca92bca6de91c5cede1d96b30a2911f3c579755ea1994a77',

            'centos:9'            => '398948e08847b7ac09a232414dc462abe9c66d098e71de3350fcb9cca38fdf0204a302d7fc75ada4fad33072371059646c4d2167baed311143240de9a8e62091',
            'centos:aarch64:9'    => 'c441a2450669fb06cc2a237a1098ab1976a49b521069e021fc81de0c34f4de97f954ac3449120f3f80963ce72a7594a449b7cd94ba89b7645397a7a8df469124',
        },
        'pcap_1_10_4' => {
            'centos:7'            => '24f30e6d52cf7a76c059734a8feb5e8e8123584cf5bc0be0097a15e3035b984b7c7c74244115b6799dad36a074c69e4aa325113d3d12912ce9719488639e8d36',

            'centos:8'            => 'd83e92009cf5f3144b0dccd95e5acd90d7620d3c68f6ce58b5f3b5b71eea7711de986d61b5a9c2544fcae6f4df8259150f031d5c08e9b312b2eed3c6816364f6',
            'centos:aarch64:8'    => '4e8d0d85021c4dabb62100428ffcb7ea37d9b9e4088486c319dd1692f169b0383be7b9fbe8a7ac7f9bcf1088b5944e211a595afb0b72f07d7f9b630ed2312ff8',

            'centos:9'            => '83e72418b59f5665062674d3ddb1c6dda2a9c022c7bf3a2dae700ff221f7dc000b22c5b775a06c2a1230d57c93decd9e2ce7482a50f9e62f99063adc201727e8',
            'centos:aarch64:9'    => '0342437fe2d0158fcf6e43fa3acba86db3d67c24aac6c6fcf5b18b766a42344c81c516d2f07d8a8619c37a3801216a508ec9db2620f111605650fc7cbe5795d2',

            'debian:9'            => '',
            'debian:10'           => '0af93960a7bf5eecb30cc133b2130d2cdf2f7a455eaa939fdf526051eaf8418a232ac48a0f31f9a6b517ae8c6c091358795afa4237dcfb2d5949cef567713f4a',

            'debian:11'           => 'e19cf14f8e9d3035d9a130286aa8b50e6d9254151f22343d56f64041d5b8f184cdddbc63d16f40724e6348e1aa06dfa721ec40bba3255e875ebd8c9d69fa0464',
            'debian:aarch64:11'   => '02214b7eae112e3a513019ba7841664d6d5b24b39a706f3176a9a8f0a9852b74d961ae64fb85979521f1016c1a14f4ee104edbf40ffc664018e01a0efd8c540b',

            'debian:12' => '2a78c9c3fec589be3a72c672a70b2ec980fca490a89724cbf593ee71779e94b5f5f40ad4b15bc0364e659f324f5576dcb8e629dcbb1833fbdb045c6bd65ce90b',
            'debian:aarch64:12' => '008d6ebf8428097f2a06ffbafb72cd0175765cff97dbc10e6b17eb21e7734d5dd56cbb834090a32f2bf94858668aa1f9512d9a208a92a1f3fea08f82480af088',

            'ubuntu:16.04'        => '7bcdfe05c80157e38f06e0ae1fb21ef3612594359b05a1690268d7d71bb93c8c3e4d3a19f18c31becdcf7e77828dfebaa7d251f017e72e794c94ec268a100e4f',
            'ubuntu:18.04'        => 'b1739570df8d97212b39ad7e98a8df7f27e42132dd1009969641c0c9bd18342b4516952b8fb116ef371ab0b1f736f0c2de3ec207776e1a09c9ea94b44d0bbdc3',

            'ubuntu:20.04'        => 'ee5120c695ca1f8f3db7d546c77f150c1e7e7734dfdf4975b0c2e8e5d33ffeac0260e1161cf4a354f92c0ab8e3d4bdb74e9c85f94c28a0259f5d8edd4d6dca3c',
            'ubuntu:aarch64:20.04'=> 'f1b43b581968b4cb9368eefe4b41f98678ad05b12623a1ad0ea8a03753094d8b5eecc8b9fe585dfd2f3b4ef5d7c4afc7c2e13e68a14d5b06cead53db478a7c86',

            'ubuntu:22.04'        => '6b941f3ea3f0131257adc6405cf4a9b81239ebc8cd005406bf3407e2dc063cfd427d0c8b24af8b212384e6e6adc44aa9f85c967af3e8af807e6b3c65b4c469ad',
            'ubuntu:aarch64:22.04'=> '4a43f189d246b9d83f2470980ca83459e1f5b728ef29a3960e5ca3a3ada3258afcb5834bedbd4f4f909db7762049947c37521b1355cc770b12ae7adbf919ee09',
        }
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
            die "Binary hash does not exist for $package, please create at least empty hash structure for it in binary_build_hashes\n";
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
