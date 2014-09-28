#!/bin/bash

#    Copyright (C) Rob Power 2014
#    This file is part of Nook® Resigner.
#
#    Nook® Resigner is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Nook® Resigner is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Nook® Resigner.  If not, see <http://www.gnu.org/licenses/>.
#
#    Nook® NOOK is a trademark of barnesandnoble.com llc or its affiliates.
#
# #####################

#	Filename: NookResigner.sh
#   Program Name: Nook® Resigner
#		  https://github.com/robpower/NookResigner
#	 Version: 1.0.0
#         Author: Rob Power <dev [at] robpower.info>
#	 Website: http://blog.robpower.info
#		  https://github.com/robpower
#		  https://www.gitorious.org/~robpower
#  Last Modified: 29/09/2014
#    Description: This Bash script automates the steps to resign your Nook®
#                 files that were previously signed with B&N keys in order
#                 to allow system apps modifications.
#                 The script can also optionally patch ReaderRMSDK in order
#                 to use external apk file and convert original dictionaries.
#                 ReaderRMSDK modification as well as Lookup application was
#                 developed by RenateRST from XDA forum
#                 ( http://forum.xda-developers.com/member.php?u=4474482,
#                 http://www.temblast.com/ ): I would like to specially
#                 thank her for her work as well as user 'ApokrifX' from XDA
#                 ( http://forum.xda-developers.com/member.php?u=4107074 )
#                 for his help in OpenSSL understanding.
#
# #######################################################################




VERSION=1.0
key1_files=(Launcher.apk GoogleSearch.apk LatinIME.apk UserDictionaryProvider.apk GlobalSearch.apk ContactsProvider.apk ApplicationsProvider.apk)
key3_files=(Phone.apk QuickStartActivity.apk TtsService.apk CertInstaller.apk WaveformDownloader.apk Settings.apk BnAuthenticationService.apk CryptoServer.apk PackageInstaller.apk TelephonyProvider.apk AccountAndSyncSettings.apk SettingsProvider.apk SysChecksum.apk DeviceManager.apk ServiceOne.apk NookHWTest.apk DemoMode.apk ../framework/framework-res.apk)
key4_files=(Social.apk ReaderRMSDK.apk Library.apk Shop.apk ThumbnailService.apk DownloadAdmin.apk MediaProvider.apk Oobe.apk CloudService.apk Home.apk Gallery.apk NookCommunity.apk DrmProvider.apk Accessories.apk AFfileDownloadService.apk DownloadProvider.apk)
key5_files=(HTMLViewer.apk Browser.apk Music.apk DeviceRegistrator.apk BnCloudRequestSvc.apk PicoTts.apk)

#directories=(system/app system/framework)
bn_key=(308204963082037ea0030201020209008b88f1a6733e568b300d06092a864886f70d010105050030818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d301e170d3130313031333230323732375a170d3337313132303230323732375a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d30820120300d06092a864886f70d01010105000382010d00308201080282010100bae4bfcefe9256daf6606769d08cc3f90aa31076b68b0cdbe903e687107a39a7672650e964eb053b4324dd9736fbf5103c3bf998303c8fc66487cb25ec1f0e9befa3ee213f064be246e880139495717b91f0c206dd79c4157b92a198efdeeba877cf047e742c1b293492dee85a232b2b76d289c41f32e37aa80d896d12d84d053bd2d7e29070579877b5887075cd4158973e5b00b9dc688b3ddb114327524ec05bdf256cfc9421e794c04158eb2d3592928424b81a47ff894d56c24411bc5d200b61102f63ad4432ca84761d23e026e14784b98ce93ad38874bcc4b9fbdd9c444301c58f37bb90663061b5ebc7efd6c5451e83764621a6bbde8e937981c5c559020103a381f63081f3301d0603551d0e04160414f3d85e4c9916bbaf53758247eaf703cfa39d483b3081c30603551d230481bb3081b88014f3d85e4c9916bbaf53758247eaf703cfa39d483ba18194a4819130818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d8209008b88f1a6733e568b300c0603551d13040530030101ff300d06092a864886f70d01010505000382010100ae4cb3e57dfc2428d13f788c7141269056ee877be2dc529caea562b8c55de6c2ad5292b7cd0ec0b8fa50957150b412d64ffca20e451745d27dd80ceccfa2a90a5cdafbe827bf21f3d5b25fd547167789dbddcd32ebfe15836ee7dfb95edb23169712bfab10afa6c4bcc5b9fd92adb644ff5c17ebe11a2608389f6ed899004634cf845585ed520690fa5496be1f730bc954f18f6443e8cf9a4e8294f61102fb596de37eeac58ff8efa63c768763b05df913907bbf940cc61cd0a57f2c2997e587318ab9c330256ae7275aabb30d5ac1408f285a1cae0d615a166fecd385ce1709688cbbc9798eaf090481ded87d97a4f0e3a62d79b2b5012e373eb0e7ad05c7d5 308204963082037ea003020102020900ac322650ceea7dd4300d06092a864886f70d010105050030818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d301e170d3130313031333230323732325a170d3337313132303230323732325a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d30820120300d06092a864886f70d01010105000382010d00308201080282010100b1e5c5205cdf28749410055834c24d5c40bf1f31bf500f6f639fc10dcf0c72af5edb90ba9b0d9a9d94fd793259c0116aae4bbf96dcb4326ae49c36bd0b6e8c111122cb98914a7476fae159ecd07533cc082fe30bd38007971c675d0c85dd5b63e5feca07327edb8b5ecbd06727225b28cd7e2290197dc094c51e4477a2165b38e330861230977624c05f5d5932776aeec261b6d2b47500a07668c6fa4d0b46a527534474bfa2373d3255430a30515141e69332cf2e3ac9bf21a7d12ca2d568a4471788ed8637363982147a00cb4ceb030f1378c645ff4d5b8e9ee26c2c0684cbd6675737ab3454c47d79647dc868087f4f31dc7985251c18b32cf52e14ca8a75020103a381f63081f3301d0603551d0e041604149a8a0eb1b772075ef0985e37e1aa4fffdae4a73e3081c30603551d230481bb3081b880149a8a0eb1b772075ef0985e37e1aa4fffdae4a73ea18194a4819130818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d820900ac322650ceea7dd4300c0603551d13040530030101ff300d06092a864886f70d010105050003820101004519fa2397078887ced0ee7a324db609e6e75c845c69af1e6eb65bd9f4df9d4077f4f41bf1ff9bf80419fe6cb54795326a5838dfd685a492505928240c6fefd86c8096813754d4f5bd0963b7cecd34e6ebc3d27fbd8c56b783b14cfe30df70ed34275fa2ac4eeec51ca95d8c707c96b5c8333a336e5f4f8448f33e0189a33f74a4da06574e6313e13b1013be49dce5ac5565a07bf0c099d67cb49e24a770b22f8e9c6b63367c812d33d6d76b96130e198c917c9c238064695106ede817cb19f4e905cde44162f56c8b5ee0314e8574b54c91e1ac95bea3c5f72c2a23e6cc957180814bc3d81abb4df789329f1fd37838b1d6650f0e517b2df18d677f8d837bd3 308204963082037ea003020102020900cf3f932a951891a5300d06092a864886f70d010105050030818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d301e170d3130313031333139353135395a170d3337313132303139353135395a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d30820120300d06092a864886f70d01010105000382010d00308201080282010100f0508805a0db588fc2fcc6ec7a6a0f34ab26c4c7e85c1af7e8a51210bffde57fa164e7ebd03712a517d2777a040d9071b857f37f4a8f1286ea8b5690e0538ee580307989c94267da491d42bfc343f3f0f5129b39a280927dd1bd03aa1c673a6460b66c925c72a700037deca6d3cb92ff71182d3630ab9b1ea6cd57b64d833eae9dc656f69499b3c456744ba431ae4dd43aa25844de9d6206e43c0f9a7020ffefbc6574dae52c217afe6ea53f9dccc0307d132c76ae947b3cf2f942ff039365801caca71470f31e30806938a36f917ae34183613ef814562d78f16fed2cf767e676da640a9e01f29b5b379ceb0727c807cb23d7773dbf01cbbef4acb72436dbe9020103a381f63081f3301d0603551d0e04160414284a13d2304d2cab8fcedbb0ecc540becc200ed53081c30603551d230481bb3081b88014284a13d2304d2cab8fcedbb0ecc540becc200ed5a18194a4819130818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d820900cf3f932a951891a5300c0603551d13040530030101ff300d06092a864886f70d01010505000382010100123483c240fe56fcce9dbd448f02325a0958dec0e71580143fad7fdbe45a2595b4d51486fdcb9ca4e9a0ef05e4452376fbbd54fdde95b15d1b8080fa5db5ee27c77c9333c60f4e3bb0524e3a04e4c0156eb065e97cb363112613dc54d23ac82ed1edd411bd0d6b4700b6600f6c5d8eea77e2d491e9759c0d7b69067ef213ba09cdd3455e987515007db2b9f72cf08e29e29bc4c4caa49bcb019d10281b7338e82b6c8143a3e1ebf3c03f3ac6c5dad9327fe52a61fbe4cf0750ad7e194ea355614d6c96443d0a4973e68ba800a40cecf5e070293c37da559c1b3a1426a24153cf738c246d0331bf46eb992ff8a89a1f662d914f0c93fe447d2fd0c2ccdcf75e84 308204963082037ea003020102020900d72ae87ebc9668f7300d06092a864886f70d010105050030818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d301e170d3130313031333230323935325a170d3337313132303230323935325a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d30820120300d06092a864886f70d01010105000382010d00308201080282010100aea6f1b3ffe1535e3ca4ec206f89e822e38bc18db8d24ef3d3854e1cfce7732bb682886318dafcf874910d96b51adb65242a99759c075a0225df2220c533cab1349b89de12bf837679bcf720fa2233edee915563e74a96ac59f2ba230ce9cebfa41e833f9c5fda878d6d64a33240fca8acb86a3c47ca329b2343581ff50bfbd192ee475514798eda4cf7c5993d2c7531e7c25a26f4df39dd9e9e9d1d646b7234679f7a79b8235e2223e05a66c024aaed4623a236fb62bb730fc078c2f88d1e903d8c7ff7709f6507d76a5334f5fcc708120354819e1fb766ad36a7ccf7159f440a3337db07ca2497011ddd20979b40f89034f8065b4d980f16d0762dd37f73f5020103a381f63081f3301d0603551d0e04160414683710db91ed3666014e7dad7aa032dfff3bfa173081c30603551d230481bb3081b88014683710db91ed3666014e7dad7aa032dfff3bfa17a18194a4819130818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31193017060355040a13104261726e657320416e64204e6f626c65310d300b060355040b13044e6f6f6b310d300b060355040313044e6f6f6b311d301b06092a864886f70d010901160e616368616e40626f6f6b2e636f6d820900d72ae87ebc9668f7300c0603551d13040530030101ff300d06092a864886f70d010105050003820101005e6072e19716ace6d3a35a10d16fa6acb6e6afbf5e12af626bff31beb8bf61fee3b5e0debb670fb3a2745c1367a9a27f6df30f256b554aa75f9c53c37dd9e9e49357949c340066b26648d4c0c38cbcc358ca6722ca54c38680d42b71c39444e3612734bac9ec2e52e3878572027d942ad4a68cea3e7b3035d8001f9d8570372fb63064ab3117b9fe18d5b63d4bf1f18472148f395ab92ff9b78bf96245bb2087cdc865c51b1ffa34fb3709d2e7cb8e2814d88b2a871a8c75fea7584af491972faea6c8e3fefe9e4eb81a4833694055bc478703e403808ddc6ca1ec9b1feceee45f8afc41be26448a00dfcd528e5833c48bbf92370e6a2fe4a8e6e57347a7e08d)
my_key=(a b c d)
#keys to resign
r=`seq 0 3`
# Default cert generation parameters
keys=(1 3 4 5)
keystores=(keys/key1 keys/key3 keys/key4 keys/key5)
export storepass='testing'
export keypass='testing'
key_alias='cert'
CN='Rob Power'
OU=Dev
O=RobPower
L=Unknown
S=Unknown
C=XX
main_d=`pwd`
original_d=nook_original
resigned_d=nook_resigned
logfile=$main_d/.log

export LC_NUMERIC="en_US.UTF-8"

#Functions
# YesNo $Question $yes $no
function yesNo {
	while true; do
		echo -e "$1\c"
		read yn
		case $yn in
			[Yy]* ) eval $2;break;;
			"" | [Nn]* ) eval $3;break;;
			* ) echo "Please answer [y]es or [n]o. (Empty answers are considered as NO)";;
		esac
	done
}

function Yesno {
	while true; do
		echo -e "$1\c"
		read yn
		case $yn in
			"" | [Yy]* ) eval $2;break;;
			[Nn]* ) eval $3;break;;
			* ) echo "Please answer [y]es or [n]o. (Empty answers are considered as YES)";;
		esac
	done
}
function YesNo {
	while true; do
		echo -e "$1\c"
		read yn
		case $yn in
			[Yy]* ) eval $2;break;;
			[Nn]* ) eval $3;break;;
			* ) echo "Please answer [y]es or [n]o.";;
		esac
	done
}

function CommandCheck {
	if (($1==0)); then
		echo "OK"
	else
		echo "FAIL (Error code: $1)"
		exit 1
	fi
}

function Mount {
	local part=$1
	local mode=$2
	case $part in
		system)
			local d=/dev/block/mmcblk0p5
			;;

		data)
			local d=/dev/block/mmcblk0p8
			;;
	esac
	adb shell "mount -o remount,$mode $d /$part" &>> $logfile
}

function Eject {
	local result=0
	local devs=`dmesg|grep 'scsi'|grep 'NOOK'|tail -n 2|awk '{print $3}'`
	echo -e " (Unmounting Nook devices ... \c"
	for num in $devs; do
		local dev=`dmesg|grep $num|grep 'Attached'|tail -n 1|cut -d '[' -f3|cut -d ']' -f1`
		if grep -qs $num /proc/mounts; then
			sudo eject /dev/$dev
		fi
		result=$(($result|$?))
	done
	sleep 7
	if (($?==0)); then
		echo -e "OK) ... \c"
	else
		echo "FAIL!!"
	fi
}

function spinner {
	sleep 2
	local pid=$1
	local delay=0.75
	local spinstr='|/-\'
	local name=''
	local length=''
	if ! [ -z $2 ]; then
		name=$2
		case $name in
			english.db)
				length=32261120;;
			bio-geo.db)
				length=3569664;;
		esac
	fi
	while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
		local temp=${spinstr#?}
		if ! [ -z $name ]; then
			copied=`ls -l $main_d/DB/|grep "$name$"|  awk '{print $5}'`
			perc=$(echo "scale = 2;(100 * $copied / $length);" |bc -l)
			printf " [%c] %05.2f %% " "$spinstr" "$perc"
		else
			printf " [%c]         " "$spinstr"
		fi
		local spinstr=$temp${spinstr%"$temp"}
		sleep $delay
		printf "\b\b\b\b\b\b\b\b\b\b\b\b\b"
	done
	printf "    \b\b\b\b"
}
function SetKeyParam {
	echo -e "\t\t Default keyring location is ${keystores[*]}."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert keystore location:' keystores" "break"
	echo -e "\t\t Default  Keyring Password is $storepass."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new password for Keyring:' storepass" "break"
	echo -e "\t\t Default Private Key Password is $keypass."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new password for Private Key:' keypass" "break"
	echo -e "\t\t Default Key Alias is $key_alias."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new Key Alias:' key_alias" "break"
	echo -e "\t\t Default certificate CN is $CN."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new CN:' CN" "break"
	echo -e "\t\t Default certificate OU is $OU."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new OU:' OU" "break"
	echo -e "\t\t Default certificate O is $O."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new O:' O" "break"
	echo -e "\t\t Default certificate L is $L."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new L:' L" "break"
	echo -e "\t\t Default certificate S is $S."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new S:' S" "break"
	echo -e "\t\t Default certificate C is $C."
	yesNo "\t\t\t Do you want to change it? [y/N]" "read -p '\t\tInsert new C:' C" "break"

}
function GenerateKey {
	mkdir -p $main_d/keys
	echo -e "\n\t Generating personal keys to sign the files "
	SetKeyParam
	for keystore in ${keystores[@]}; do
		if [ -f $keystore ]; then
			keytool -list -keystore $main_d/$keystore -storepass:env storepass &>> $logfile
			if (($?==0)); then
				a=`keytool -list -keystore $main_d/$keystore -storepass:env storepass |grep PrivateKeyEntry|cut -d ',' -f1`
				echo -e $a |grep -Fx $key_alias &>> $logfile
				if (($?==0)); then
					echo -e "key already exists, won't generate"
					continue
				fi
			else
				echo -e "ERROR: Keyring already exists but password might be incorrect\n\t\t Exiting."
				exit 1
			fi
		fi
		echo -e "\t\t Generating $keystore ... "
		keytool -genkeypair -keyalg "RSA" -sigalg "SHA1withRSA" -validity 10000 -alias $key_alias -keystore $main_d/$keystore -storepass:env keypass -keypass:env  keypass -dname "CN=$CN, OU=$OU, O=$O, L=$L, S=$S, C=$C"
		CommandCheck $?
	done

}

function DepCheck {
	#Check if package is installed
	name=$2
	pack=$1
	echo -e "\t\t checking $name ... \c" 2>&1
	if [[ $(dpkg-query -f'${Status}' --show $pack 2>$logfile) = *\ installed ]]; then
		echo "OK"
	else
		echo "FAIL"
		DepSolve $name
	fi
}
function DepFileCheck {
	name=$2
	files=$1
	echo -e "\t\t checking $name ... \c"
	for f in $files; do
		if [ -f $f ]; then
			echo -e ".\c"
		else
			echo "FAIL"
			DepSolve $name
			return
		fi
	done
	echo " OK"
}
function DepCommandCheck {
	cmd=$1
	exp_exit=$2
	name=$3
	echo -e "\t\t checking $name ... \c"
	eval $cmd &>> $logfile
	if (($?==exp_exit)); then
		echo "OK"
	else
		echo "FAIL"
		DepSolve $name
	fi
}


function DepSolve {
	local result=0
	echo -e "\t\t\t   Trying to resolve unmet dependency: $1 ... \c"
	case $1 in
		lookup)
			wget http://www.temblast.com/download/Lookup-1.0.apk -O $main_d/Lookup.apk &>> $logfile
			result=$(($result|$?))
			adb install $main_d/Lookup.apk &>> $logfile
			result=$(($result|$?))
			CommandCheck $result
			;;

		sqlite-win)
			wget 'http://www.sqlite.org/snapshot/sqlite-dll-win32-x86-201409200035.zip' &>> $logfile
			result=$(($result|$?))
			unzip -oj sqlite-dll-win32-x86-201409200035.zip -d $main_d/sql &>> $logfile
			result=$(($result|$?))
			rm -f sqlite-dll-win32-x86-201409200035.zip &>> $logfile
			result=$(($result|$?))
			wget 'http://www.sqlite.org/2014/sqlite-shell-win32-x86-3080600.zip' &>> $logfile
			result=$(($result|$?))
			unzip -oj sqlite-shell-win32-x86-3080600.zip -d $main_d/sql &>> $logfile
			result=$(($result|$?))
			rm -f sqlite-shell-win32-x86-3080600.zip &>> $logfile
			result=$(($result|$?))
			CommandCheck $result
			;;
		nookdict)
			wget 'http://www.temblast.com/download/nookdict.exe' -O $main_d/sql/nookdict.exe &>> $logfile
			CommandCheck $?
			;;
		sqlite3-nook)
			cd $main_d/sql
			result=$(($result|$?))
			wget 'http://forum.xda-developers.com/attachment.php?attachmentid=1246352&d=1344315114' -O sqlite3.zip &>> $logfile
			result=$(($result|$?))
			unzip -oj sqlite3.zip &>> $logfile
			result=$(($result|$?))
			rm *.zip &>> $logfile
			result=$(($result|$?))
			cd $main_d
			result=$(($result|$?))
			Mount 'system' 'rw'
			result=$(($result|$?))
			adb push $main_d/sql/sqlite3 /system/bin/ &>> $logfile
			result=$(($result|$?))
			adb shell chmod 755 /system/bin/sqlite3 &>> $logfile
			result=$(($result|$?))
			Mount 'system' 'ro'
			result=$(($result|$?))
			CommandCheck $result
			;;

		wine)
			sudo apt-get install -y wine  winetricks &>> $logfile
			CommandCheck $?
			;;

		wine-libs)
			winetricks vcrun2005 &>> $logfile
			CommandCheck $?
			;;

		java)
			sudo apt-get install -y oracle-jdk7-installer &>> $logfile
			CommandCheck $?
			;;

		adb)
			sudo apt-get install -y android-tools-adb &>> $logfile
			result=$(($result|$?))
			mkdir -p ~/.android &>> $logfile && echo 0x2080 > ~/.android/adb_usb.ini && adb kill-server > $logfile && adb start-server &>> $logfile
			result=$(($result|$?))
			count=$(cat /etc/udev/rules.d/*-android.rules|grep -c 'SUBSYSTEMS=="usb", ATTR{idVendor}=="2080", MODE="0666", GROUP="plugdev"')
			if (($count==0)); then
				echo 'SUBSYSTEMS=="usb", ATTR{idVendor}=="2080", MODE="0666", GROUP="plugdev"' | sudo tee -a /etc/udev/rules.d/98-android.rules &>> $logfile && sudo udevadm control --reload-rules &>> $logfile
			result=$(($result|$?))
			fi
			CommandCheck $result
			;;

		apktool)
			mkdir -p $main_d/apktool &>> $logfile
			result=$(($result|$?))
			cd $main_d/apktool &>> $logfile
			result=$(($result|$?))
			wget 'https://android-apktool.googlecode.com/files/apktool1.5.2.tar.bz2' &>> $logfile
			result=$(($result|$?))
			wget 'https://android-apktool.googlecode.com/files/apktool-install-linux-r05-ibot.tar.bz2' &>> $logfile
			result=$(($result|$?))
			tar xjvf apktool1.5.2.tar.bz2 &>> $logfile && tar xjvf apktool-install-linux-r05-ibot.tar.bz2  &>> $logfile && mv -f apktool1.5.2/* ./  &>> $logfile && mv -f apktool-install-linux-r05-ibot/* ./  &>> $logfile && rm -rf apktool1.5.2 apktool-install-linux-r05-ibot *.tar.bz2 &>> $logfile && sudo cp * /usr/local/bin/ &>> $logfile
			result=$(($result|$?))
			CommandCheck $result
			cd $main_d
			;;

		mergesmali)
			wget 'http://www.temblast.com/download/mergesmali.exe' -O $main_d/mergesmali/mergesmali.exe &>> $logfile
			CommandCheck $?
			;;

		nook121patch)
			wget 'http://www.temblast.com/download/nook121patch.zip' &>> $logfile
			result=$(($result|$?))
			unzip -o nook121patch.zip -d "$main_d/nook121patch" &>> $logfile
			result=$(($result|$?))
			rm -f nook121patch.zip
			result=$(($result|$?))
			CommandCheck $result
			;;

		zipalign)
#			mkdir -p $main_d/sdk
#			$main_d/sdk
#			wget 'https://dl.google.com/android/adt/adt-bundle-linux-x86-20140702.zip'
#			unzip -o 'adt-bundle-linux-x86-20140702.zip'
#			rm 'adt-bundle-linux-x86-20140702.zip'
#			echo -e "# zipalign include
#			`pwd`/adt-bundle-linux-x86-20140702/sdk/build-tools/android-4.4W">> ~/.bashrc
			echo -e "\n\t\t Unable to locate 'zipalign' binary.
please download android SDK studio and add \<build-tools> directory to your '~/.bashrc' file and restart bash.

i.e. echo -e '#zipalign include
<path to android sdk>\build-tools/android-4.4W' > ~/.bash.rc
bash"
			exit 1;;
	esac
}

# ################ #
# Program routines #
# ################ #
function disclaimer {
	clear

	echo -e "\n\n\t Welcome to the Nook 1.21 ReaderSDK patching process!"
	echo -e "\n\t\t This process involves sequencial steps in order to patch your Nook® and resign the whole system folder"
	echo -e "\n\t\t !!!! DISCLAIMER !!!!"
	echo -e "\n\t\t Even if it seems to work pretty smoothly, this code is EXPERIMENTAL, "
	echo -e "\t\t intended for testing and education purpose."
	echo -e "\t\t Using it you are assuming all the resposability "
	echo -e "\t\t In case anything might go wrong, the author cannot be held responsible"
	echo -e "\t\t for any bad event, including bricking your device or killing your pet."
	echo -e "\n\t If you agree with all the above, write \"yes\": \c"

	while true; do
		read answer
		answer=$(echo $answer | awk '{print tolower($0)}')
		case $answer in
			yes) break ;;
			no)
				echo "You entered $CONFIRM: ABORTING"
				exit;;
			*) echo Please enter either yes or no

		esac
	done
}

function clean {
	echo -e "\n\t Cleaning old files if existing..."
	rm -rf $original_d $resigned_d cert
	rm -f nook_*.zip cert.* CERT.*

	mkdir -p $main_d/DB
	mkdir -p $main_d/keys
	mkdir -p $main_d/nook121patch
	mkdir -p $main_d/mergesmali
	mkdir -p $main_d/sql
}

function dep_check {
	# Dependency check
	echo -e "\n\t Checking dependencies"
	# Checking Java
	DepCheck "oracle-jdk7-installer" "java"

	# Checking Wine
	DepCheck "wine" "wine"

	# Checking vcrun2005
	DepCommandCheck "winetricks list-installed|grep -c 'vcrun2005'" '0' 'wine-libs'

	# Checking apktool & aapt
	DepFileCheck "/usr/local/bin/apktool.jar /usr/local/bin/apktool /usr/local/bin/aapt" "apktool"

	# Checking Mergesmali
	DepFileCheck "mergesmali/mergesmali.exe" "mergesmali"

	# Checking patch files
	DepFileCheck "nook121patch/ReaderMainView.smali" "nook121patch"

	# Checking sqlite for win
	DepFileCheck "sql/sqlite3.dll sql/sqlite3.dll" "sqlite-win"


	# Checking nookdict
	DepFileCheck "sql/nookdict.exe" "nookdict"

	# Checking zipalign
	DepCommandCheck "zipalign" "2" "zipalign"

	# Checking ADB
	DepCommandCheck 'adb usb' '0' 'adb'

	echo -e "\t\t ADB: Waiting for device ... \c"
	adb 'wait-for-device'
	sleep 8
	Eject
	echo "OK"
	# Checking sqlite3 on Nook
	DepCommandCheck "adb shell 'if [ -f /system/bin/sqlite3 ]; then echo 0; else echo 1; fi'|grep -c 0" '0' 'sqlite3-nook'

	# Checking Lookup app on Nook
	DepCommandCheck "adb shell 'if [ -f /data/app/com.temblast.lookup.apk ]; then echo 0; else echo 1; fi'|grep -c 0" '0' 'lookup'


	echo -e "\n\t Dependency check passed."
}

# CONVERTING DBs
function convert_old_dictionaries {
	echo -e "\n\t Now proceeding to download and convert original dictionaries to new format."
	echo -e "\n\t\t Downloading dictionaries .\c"

	adb pull /system/media/reference/basewords.db $main_d/DB/ &>> $logfile
	echo -e ".\c"
	adb pull /system/media/reference/bgwords.db $main_d/DB/ &>> $logfile
	echo ". OK"
	echo -e "\t\t\t Converting English dictionary (be patient, this will take a lot!) ... \c"
	cd $main_d/DB &>> $logfile
	wine ../sql/nookdict /c /d basewords.db english.db &>> $logfile &
	spinner $! english.db
	CommandCheck $?
	echo -e "\t\t\t Converting Bio-Geo dictionary ... \c"
	wine ../sql/nookdict /c /d bgwords.db bio-geo.db &>> $logfile &
	spinner $! bio-geo.db
	CommandCheck $?
	cd $main_d &>> $logfile
}
function upload_dict {
	result=0
	echo -e "\n\t Uploading dictionaries to SD card ... \c"
	Eject
	result=$(($result|$?))
	adb shell "mkdir /sdcard/Dictionaries" &>> $logfile
	adb push $main_d/DB/english.db /sdcard/Dictionaries/english.db &>> $logfile
	result=$(($result|$?))
	adb push $main_d/DB/bio-geo.db /sdcard/Dictionaries/bio-geo.db &>> $logfile
	result=$(($result|$?))
	CommandCheck $result
}

function create_dict_index {
	#Creating indexes
	echo -e "\n\t Creating indexes:"
	echo -e "\t\t\t - english.db ... \c"
	adb shell "echo -e 'CREATE INDEX term_index on tblWords (term ASC);\n.q'|sqlite3 /sdcard/Dictionaries/english.db" &>> $logfile
	CommandCheck $?
	echo -e "\t\t\t - bio-geo.db ... \c"
	adb shell "echo -e 'CREATE INDEX term_index on tblWords (term ASC);\n.q'|sqlite3 /sdcard/Dictionaries/bio-geo.db" &>> $logfile 
	CommandCheck $?
}

function patch_resign {
	echo -e "\n\t Now starting the patch and resign process"

	# COPYING FILES
	echo -e "\n\t Proceeding to connect and copy original files"

	mkdir  -p $main_d/$original_d
	cd $main_d/$original_d
	echo -e "\t\t ADB: Waiting for device ... \c"
	adb 'wait-for-device'
	CommandCheck $?
	Yesno "\t\t Device ready: Do you want to proceed now? [Y/n]" "break" "exit"
	echo -e "\t\t Copying original files from your device... (This may take a while, please be patient!)"
	mkdir -p system/app system/framework data/system/
	in_dir="system/app"
	cd $in_dir
	err=0
	for i in $r; do
		echo -e "\t\t\t ADB: Copying files to sign with key ${keys[$i]} .\c"
		key_files=key${keys[$i]}_files[*]
		key_files=${!key_files}
		for file in ${key_files[*]}; do
			adb pull /system/app/$file $file &>> $logfile
			err=$(($err|$?))
	#	adb shell ls /$in_dir/*.apk | tr '\r' ' ' | xargs -n1 adb pull &>> $logfile 
			echo -e ".\c"
		done
		echo -e " \c"
		CommandCheck $err
	done
		echo -e "\t\t\t ADB: Copying packages.xml ... \c"
		cd $main_d/$original_d
		adb pull /data/system/packages.xml data/system/packages.xml &>> $logfile
		CommandCheck $?

	echo -e "\t\t Files successfully downloaded in $original_d."
	cd $main_d

	#rsync -avm --include='*.apk' -f 'hide,! */' $original_d/ $resigned_d &>> $logfile
	mkdir -p $original_d/META-INF/com/google/android
	echo "# Restore signed components
	mount(\"ext2\", \"/dev/block/mmcblk0p5\", \"/system\");
	package_extract_dir(\"system/app\", \"/system/app\");
	package_extract_dir(\"system/framework\", \"/system/framework\");
	unmount(\"/system\");
	# Restore packages.xml
	mount(\"ext3\", \"/dev/block/mmcblk0p8\", \"/data\");
	package_extract_dir(\"data/system/packages.xml\", \"/data/system/packages.xml\");
	unmount(\"/data\");" > $original_d/META-INF/com/google/android/updater-script


	cp -a $original_d $resigned_d


	echo -e "\t\t Creating restore zip ... \c"
	cd $main_d/$original_d
	zip -r ../nook_restore.zip * &>> $logfile
	CommandCheck $?



	if (($PATCH_READER==1)); then
		#PATCHING READER
		echo -e "\n\t Now proceeding to patch Reader APK"
		cd "$main_d/$resigned_d"
		mv system/app/ReaderRMSDK.apk ReaderRMSDK.apk
		echo -e "\t\t Installing framework ... \c"
		apktool if system/framework/framework-res.apk &>> $logfile
		CommandCheck $?
		echo -e "\t\t Decode original Reader APK ... \c"
		apktool d ReaderRMSDK.apk ReaderRMSDK &>> $logfile
		CommandCheck $?
		echo -e "\t\t Patching code with MergeSmali ... \c"
		wine ../mergesmali/mergesmali /v ReaderRMSDK/smali ../nook121Patch/ReaderMainView.smali &>> $logfile
		CommandCheck $?
		rm ReaderRMSDK.apk
		echo -e "\t\t Rebuilding patched APK ... \c"
		apktool b ReaderRMSDK ReaderRMSDK.apk &>> $logfile
		CommandCheck $?
		mv ReaderRMSDK.apk system/app/ReaderRMSDK.apk
		rm -rf ReaderRMSDK

		echo -e "\n\t Now proceeding to sign 'ReaderRMSDK.apk and to resign your whole system."
	else
		echo -e "\n\t Now proceeding to resign your whole system."
	fi
	echo -e "\n\t\t In order to do this, you will need a valid Android developer key"
	echo -e "\t\t If you already own one, you can enter its address and parameters,"
	echo -e "\t\t otherwise the program will generate one for you"
	yesNo "\t\t Do you already own a keystore? [y/N]\c" "SetKeyParam" "GenerateKey"

	#SIGNING
	echo -e "\n\t Now proceeding to sign the files"
	Yesno "\n\t\t Do you want to start signing APKs now? [Y/n]" "break" "exit"
	cd "$main_d/$resigned_d/$in_dir"


	for i in $r; do
		echo -e "\n\t Re-signing APKs with key ${keys[$i]} \c"

		key_files=key${keys[$i]}_files[*]
		key_files=${!key_files}
		err=0
		for apk in ${key_files[*]}; do
			#echo -e "\t\t$apk .\c"
	#		zip -d $apk META-INF\* &>> $logfile
			if [ "$apk" != "ReaderRMSDK.apk" ]; then
				aapt r $apk 'META-INF/CERT.SF' 'META-INF/CERT.RSA' 'META-INF/MANIFEST.MF' &>> $logfile
				#CommandCheck $?
				err=$(($err|$?))
			fi
			echo -e ".\c"
			jarsigner -verbose -keystore $main_d/${keystores[$i]} -storepass:env storepass -keypass:env keypass $apk -digestalg "SHA1" -sigalg "MD5withRSA" $key_alias  &>> $main_d/cert.log
			#CommandCheck $?
			err=$(($err|$?))
			echo -e ".\c"
			mv $apk $apk.old
			zipalign -f 4 $apk.old $apk &>> $logfile
			#CommandCheck $?
			err=$(($err|$?))
			echo -e ". \c"
			rm $apk.old
		done
		CommandCheck $err
	done

	unset storepass
	unset keypass

	# Patching Packages.xml
	echo -e "\n\t Now proceeding to patch Packages.xml"
	mkdir -p $main_d/cert
	for i in $r; do
		echo -e "\t\t Exporting key ${keys[$i]}...\c"
		# Caution
		key_files=key${keys[$i]}_files
		first_file=${!key_files}
		cp -f $first_file $main_d/cert/${keys[$i]}.zip &>> $logfile
		my_key[$i]=`unzip -ojp $main_d/cert/${keys[$i]}.zip  'META-INF/CERT.RSA' | openssl pkcs7 -inform DER -print_certs | openssl x509  -inform PEM  -outform DER | xxd -p |tr -d '\n'`
		CommandCheck $?
	done
	echo ${my_key[@]}|tr ' ' '\n'>$main_d/keys.txt

	cd $main_d/$resigned_d/data/system/
	for i in $r; do
		echo -e "\t\t Replacing key ${keys[$i]} ...\c"
		sed -i "s/${bn_key[$i]}/${my_key[$i]}/g" packages.xml &>> $logfile
		CommandCheck $?
	done

	echo -e "\n\t\t Zipping ... \c"
	cd $main_d/$resigned_d
	zip -r ../nook_dictionary.zip * &>> $logfile
	CommandCheck $?
	############


	echo -e "\n\t Trying to install through ADB"
	echo -e "\t\t\c"
	Eject
	echo -e "\n\t\t Remounting /system (RW) ... \c"
	Mount 'system' 'rw'
	CommandCheck $?
	echo -e "\t\t Remounting /data (RW) ... \c"
	Mount 'data' 'rw'
	CommandCheck $?
	echo -e "\t\t Stopping Framework... \c"
	adb shell ps | grep com.google.android.gsf | awk '{print $2}' | xargs adb shell kill
	CommandCheck $?
	result=0
	echo -e "\t\t Copying files to /system ...\c"
	adb push system/app/ /system/app &>> $logfile
	result=$(($result|$?))
	adb push system/framework/framework-res.apk /system/framework/framework-res.apk &>> $logfile
	result=$(($result|$?))
	CommandCheck $result
	echo -e "\t\t Removing file 'packages.xml' for first reboot ...\c"
	adb shell rm -f data/system/packages.xml &>> $logfile
	CommandCheck $?
	echo -e "\t\t Clearing dalvik ...\c"
	adb shell rm -r /data/dalvik-cache &>> $logfile
	CommandCheck $?
	echo -e "\t\t Till now everything look fine."
	echo -e "\n\t\t Now rebooting... Please wait..."
	echo -e "\t\t DO NOT disconnect the device."

	adb reboot
	echo -e "\t\t Waiting for device to get online again... \c"
	adb 'wait-for-device' &>> $logfile
	spinner $!
	CommandCheck $?
	echo -e "\t\t Waiting 30s to ensure 'packages.xml' regeneration... \c"
	sleep 30 &>> $logfile
	CommandCheck $?
	echo -e "\t\t\c"
	Eject
	echo -e "\n\t\t Remounting /data (RW) ...\c"
	Mount 'data' 'rw'
	CommandCheck $?
	echo -e "\t\t Pushing patched 'Packages.xml' \c"
	adb push data/system/packages.xml /data/system/packages.xml &>> $logfile
	CommandCheck $?
	echo -e "\t\t Rebooting your Nook® \c"
	adb reboot
	CommandCheck $?
	echo -e "\n\t\t Removing backups ... \c"
	cd $main_d
	rm -rf $original_d $resigned_d
	CommandCheck $?

	echo -e "\n\n\t Process completed with SUCCESS! \
	\n\n\t\t >>> Congratulations! \
	\n\n\t\t Your 'Reader' application has been patched and \
	\n\t\t your whole system have been resigned with BN-free keys.\
	\n\t\t In case you might need to patch and resign any system app,\
	\n\t\t please save your generated keystores for future use:\
	\n\n\t\t\t cert index 1 (user='android.uid.shared'  uid='10002'):\
	\n\t\t\t\t stored in '${keystores[0]}' \
	\n\t\t\t cert index 3 (user='android.media'       uid='10000'),\
	\n\t\t\t\t      (user='android.uid.phone'   uid='1001'):\
	\n\t\t\t\t stored in ${keystores[1]} \
	\n\t\t\t cert index 4: (user='android.uid.system' uid='1000'):\
	\n\t\t\t\t stored in ${keystores[2]} \
	\n\t\t\t cert index 5 : (user='com.bn.cloud'      uid='10003'):\
	\n\t\t\t\t stored in ${keystores[3]} \
	\n\n\t\t In order to install new dictionaries, copy \
	\n\t\t them in your SD card 'Dictionaries' folder. \
	\n\t\t\t 'nook_dictionary.zip' --> To install the patched files\
	\n\t\t\t 'nook_restore.zip'  --> To restore in case of trouble\
	\n\n\t Enjoy! "
}

function restore {
	case $1 in
		"")
			backup=nook_original.zip
		;;
		*)
			backup=$1
			;;
	esac
	unzip $backup -d restore

echo -e "\n\t Trying to restore from backup [$backup]"
	echo -e "\t\t\c"
	Eject
	echo -e "\n\t\t Remounting /system (RW) ... \c"
	Mount 'system' 'rw'
	CommandCheck $?
	echo -e "\t\t Remounting /data (RW) ... \c"
	Mount 'data' 'rw'
	CommandCheck $?
	echo -e "\t\t Stopping Framework... \c"
	adb shell ps | grep com.google.android.gsf | awk '{print $2}' | xargs adb shell kill
	CommandCheck $?
	result=0
	echo -e "\t\t Copying files to /system ...\c"
	adb push restore/system/app/ /system/app/ &>> $logfile
	result=$(($result|$?))
	adb push restore/system/framework/framework-res.apk /system/framework/framework-res.apk &>> $logfile
	result=$(($result|$?))
	CommandCheck $result
	echo -e "\t\t Restoring 'packages.xml'...\c"
	adb push restore/data/system/packages.xml /data/system/packages.xml &>> $logfile
	CommandCheck $?
	echo -e "\t\t Clearing dalvik ...\c"
	adb shell rm -r /data/dalvik-cache &>> $logfile
	CommandCheck $?
	echo -e "\t\t Rebooting ...\c"
	adb reboot
	CommandCheck
	echo -e "\n\t Your backup has been restored. \n\t Please wait for device to reboot."

}



# ############ #
# SCRIPT START #
# ############ #

# set an initial value for the flags
PATCH_READER=0
DICTIONARY_CONVERT=0
DICTIONARY_UPLOAD=0
DICTIONARY_INDEX=0
ONLY_DEP=0

# read the options
TEMP=`getopt -o cdhpr:v --long check-dep,dict-full,dict-index,dict-upload,help,version,patch-reader,restore: \
             -n 'Nookresigner.sh' -- "$@"`

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"

# extract options and their arguments into variables.
#while true ; do
while true; do
    case "$1" in
	-h|--help)
		echo -e "Nook® Resigner v. $VERSION"
		echo -e "\n\t Usage: NookResigner.sh [OPTIONS]"
		echo -e "\n\t Default behaviour:"
		echo -e "\n\t\t Resigns all the files previously signed with B&N keys using personal keys."
		echo -e "\n\t OPTIONS:"
		echo -e "\t -c, --check-dep \t Only checks for dependecies and exits."
		echo -e "\t -p, --patch-reader \t Also patches 'ReaderSMDK.apk' to lookup alternative dictionaries."
		echo -e "\t -d, --dict-full \t Also converts original DBs from your Nook®."
		echo -e "\t     --dict-upload \t Uploads pre-converted 'english.db' and 'bio-geo.db' DBs to your Nook® SD card."
		echo -e "\t     --dict-index \t Create indexes in your uploaded 'english.db' and 'bio-geo.db' DBs."
		echo -e "\t -r FILE, --restore=FILE Restore from backup zip."
		echo -e "\t -v, --version \t\t Show version info."
		echo -e "\t -h, --help \t\t Print this help text."
		exit 0;;

	-v|--version)
		echo -e "Nook® Resigner v. $VERSION"
		exit 0;;

        --)
		echo '--'
		shift
		break ;;

	-p|--patch-reader)
		PATCH_READER=1;
		shift
		;;

	-d|--dict-full)
		DICTIONARY_CONVERT=1
		DICTIONARY_UPLOAD=1
		DICTIONARY_INDEX=1
		shift;;

	--dict-upload)
		DICTIONARY_UPLOAD=1
		shift
		;;
	--dict-index)
		DICTIONARY_INDEX=1
		shift
		;;
	-c|--check-dep)
		clean
		dep_check
		exit 0;;
	-r|--restore)
		disclaimer
		restore $1
		exit 0;;

        *)
		echo '*'
		break ;;
    esac
done
# argument debug string
# echo "dep $ONLY_DEP dict $DICTIONARY_CONVERT $DICTIONARY_UPLOAD $DICTIONARY_INDEX patch$PATCH_READER"
if (($ONLY_DEP==0)); then
	disclaimer
fi
clean
dep_check
if (($ONLY_DEP==0)); then
	if (($DICTIONARY_CONVERT==1)); then
		convert_old_dictionaries
	fi
	if (($DICTIONARY_UPLOAD==1)); then
		upload_dict
	fi
	if (($DICTIONARY_INDEX==1)); then
		create_dict_index
	fi
	patch_resign
fi



