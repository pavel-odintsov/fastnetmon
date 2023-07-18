#include "iana_ip_protocols.hpp"
#include <boost/algorithm/string.hpp>
#include <iostream>

const char* get_ip_protocol_name_by_number_iana(uint8_t protocol_number) {
    switch (protocol_number) {
    case 0:
        return "HOPOPT";
        break;
    case 1:
        return "ICMP";
        break;
    case 2:
        return "IGMP";
        break;
    case 3:
        return "GGP";
        break;
    case 4:
        return "IPV4";
        break;
    case 5:
        return "ST";
        break;
    case 6:
        return "TCP";
        break;
    case 7:
        return "CBT";
        break;
    case 8:
        return "EGP";
        break;
    case 9:
        return "IGP";
        break;
    case 10:
        return "BBN_RCC_MON";
        break;
    case 11:
        return "NVP_II";
        break;
    case 12:
        return "PUP";
        break;
    case 13:
        return "ARGUS_DEPRECATED";
        break;
    case 14:
        return "EMCON";
        break;
    case 15:
        return "XNET";
        break;
    case 16:
        return "CHAOS";
        break;
    case 17:
        return "UDP";
        break;
    case 18:
        return "MUX";
        break;
    case 19:
        return "DCN_MEAS";
        break;
    case 20:
        return "HMP";
        break;
    case 21:
        return "PRM";
        break;
    case 22:
        return "XNS_IDP";
        break;
    case 23:
        return "TRUNK_1";
        break;
    case 24:
        return "TRUNK_2";
        break;
    case 25:
        return "LEAF_1";
        break;
    case 26:
        return "LEAF_2";
        break;
    case 27:
        return "RDP";
        break;
    case 28:
        return "IRTP";
        break;
    case 29:
        return "ISO_TP4";
        break;
    case 30:
        return "NETBLT";
        break;
    case 31:
        return "MFE_NSP";
        break;
    case 32:
        return "MERIT_INP";
        break;
    case 33:
        return "DCCP";
        break;
    case 34:
        return "THREEPC";
        break;
    case 35:
        return "IDPR";
        break;
    case 36:
        return "XTP";
        break;
    case 37:
        return "DDP";
        break;
    case 38:
        return "IDPR_CMTP";
        break;
    case 39:
        return "TPPPPP";
        break;
    case 40:
        return "IL";
        break;
    case 41:
        return "IPV6";
        break;
    case 42:
        return "SDRP";
        break;
    case 43:
        return "IPV6_ROUTE";
        break;
    case 44:
        return "IPV6_FRAG";
        break;
    case 45:
        return "IDRP";
        break;
    case 46:
        return "RSVP";
        break;
    case 47:
        return "GRE";
        break;
    case 48:
        return "DSR";
        break;
    case 49:
        return "BNA";
        break;
    case 50:
        return "ESP";
        break;
    case 51:
        return "AH";
        break;
    case 52:
        return "I_NLSP";
        break;
    case 53:
        return "SWIPE_DEPRECATED";
        break;
    case 54:
        return "NARP";
        break;
    case 55:
        return "MOBILE";
        break;
    case 56:
        return "TLSP";
        break;
    case 57:
        return "SKIP";
        break;
    case 58:
        return "IPV6_ICMP";
        break;
    case 59:
        return "IPV6_NONXT";
        break;
    case 60:
        return "IPV6_OPTS";
        break;
    case 61:
        return "UNKNOWN_61";
        break;
    case 62:
        return "CFTP";
        break;
    case 63:
        return "UNKNOWN_63";
        break;
    case 64:
        return "SAT_EXPAK";
        break;
    case 65:
        return "KRYPTOLAN";
        break;
    case 66:
        return "RVD";
        break;
    case 67:
        return "IPPC";
        break;
    case 68:
        return "UNKNOWN_68";
        break;
    case 69:
        return "SAT_MON";
        break;
    case 70:
        return "VISA";
        break;
    case 71:
        return "IPCV";
        break;
    case 72:
        return "CPNX";
        break;
    case 73:
        return "CPHB";
        break;
    case 74:
        return "WSN";
        break;
    case 75:
        return "PVP";
        break;
    case 76:
        return "BR_SAT_MON";
        break;
    case 77:
        return "SUN_ND";
        break;
    case 78:
        return "WB_MON";
        break;
    case 79:
        return "WB_EXPAK";
        break;
    case 80:
        return "ISO_IP";
        break;
    case 81:
        return "VMTP";
        break;
    case 82:
        return "SECURE_VMTP";
        break;
    case 83:
        return "VINES";
        break;
    case 84:
        return "IPTM_OR_TTP";
        break;
    case 85:
        return "NSFNET_IGP";
        break;
    case 86:
        return "DGP";
        break;
    case 87:
        return "TCF";
        break;
    case 88:
        return "EIGRP";
        break;
    case 89:
        return "OSPFIGP";
        break;
    case 90:
        return "SPRITE_RPC";
        break;
    case 91:
        return "LARP";
        break;
    case 92:
        return "MTP";
        break;
    case 93:
        return "AX_25";
        break;
    case 94:
        return "IPIP";
        break;
    case 95:
        return "MICP_DEPRECATED";
        break;
    case 96:
        return "SCC_SP";
        break;
    case 97:
        return "ETHERIP";
        break;
    case 98:
        return "ENCAP";
        break;
    case 99:
        return "UNKNOWN_99";
        break;
    case 100:
        return "GMTP";
        break;
    case 101:
        return "IFMP";
        break;
    case 102:
        return "PNNI";
        break;
    case 103:
        return "PIM";
        break;
    case 104:
        return "ARIS";
        break;
    case 105:
        return "SCPS";
        break;
    case 106:
        return "QNX";
        break;
    case 107:
        return "A_N";
        break;
    case 108:
        return "IPCOMP";
        break;
    case 109:
        return "SNP";
        break;
    case 110:
        return "COMPAQ_PEER";
        break;
    case 111:
        return "IPX_IN_IP";
        break;
    case 112:
        return "VRRP";
        break;
    case 113:
        return "PGM";
        break;
    case 114:
        return "UNKNOWN_114";
        break;
    case 115:
        return "L2TP";
        break;
    case 116:
        return "DDX";
        break;
    case 117:
        return "IATP";
        break;
    case 118:
        return "STP";
        break;
    case 119:
        return "SRP";
        break;
    case 120:
        return "UTI";
        break;
    case 121:
        return "SMP";
        break;
    case 122:
        return "SM_DEPRECATED";
        break;
    case 123:
        return "PTP";
        break;
    case 124:
        return "ISISOVERIPV4";
        break;
    case 125:
        return "FIRE";
        break;
    case 126:
        return "CRTP";
        break;
    case 127:
        return "CRUDP";
        break;
    case 128:
        return "SSCOPMCE";
        break;
    case 129:
        return "IPLT";
        break;
    case 130:
        return "SPS";
        break;
    case 131:
        return "PIPE";
        break;
    case 132:
        return "SCTP";
        break;
    case 133:
        return "FC";
        break;
    case 134:
        return "RSVP_E2E_IGNORE";
        break;
    case 135:
        return "MOBILITYHEADER";
        break;
    case 136:
        return "UDPLITE";
        break;
    case 137:
        return "MPLS_IN_IP";
        break;
    case 138:
        return "MANET";
        break;
    case 139:
        return "HIP";
        break;
    case 140:
        return "SHIM6";
        break;
    case 141:
        return "WESP";
        break;
    case 142:
        return "ROHC";
        break;
    case 143:
        return "ETHERNET";
        break;
    case 144:
        return "UNASSIGNED_144";
        break;
    case 145:
        return "UNASSIGNED_145";
        break;
    case 146:
        return "UNASSIGNED_146";
        break;
    case 147:
        return "UNASSIGNED_147";
        break;
    case 148:
        return "UNASSIGNED_148";
        break;
    case 149:
        return "UNASSIGNED_149";
        break;
    case 150:
        return "UNASSIGNED_150";
        break;
    case 151:
        return "UNASSIGNED_151";
        break;
    case 152:
        return "UNASSIGNED_152";
        break;
    case 153:
        return "UNASSIGNED_153";
        break;
    case 154:
        return "UNASSIGNED_154";
        break;
    case 155:
        return "UNASSIGNED_155";
        break;
    case 156:
        return "UNASSIGNED_156";
        break;
    case 157:
        return "UNASSIGNED_157";
        break;
    case 158:
        return "UNASSIGNED_158";
        break;
    case 159:
        return "UNASSIGNED_159";
        break;
    case 160:
        return "UNASSIGNED_160";
        break;
    case 161:
        return "UNASSIGNED_161";
        break;
    case 162:
        return "UNASSIGNED_162";
        break;
    case 163:
        return "UNASSIGNED_163";
        break;
    case 164:
        return "UNASSIGNED_164";
        break;
    case 165:
        return "UNASSIGNED_165";
        break;
    case 166:
        return "UNASSIGNED_166";
        break;
    case 167:
        return "UNASSIGNED_167";
        break;
    case 168:
        return "UNASSIGNED_168";
        break;
    case 169:
        return "UNASSIGNED_169";
        break;
    case 170:
        return "UNASSIGNED_170";
        break;
    case 171:
        return "UNASSIGNED_171";
        break;
    case 172:
        return "UNASSIGNED_172";
        break;
    case 173:
        return "UNASSIGNED_173";
        break;
    case 174:
        return "UNASSIGNED_174";
        break;
    case 175:
        return "UNASSIGNED_175";
        break;
    case 176:
        return "UNASSIGNED_176";
        break;
    case 177:
        return "UNASSIGNED_177";
        break;
    case 178:
        return "UNASSIGNED_178";
        break;
    case 179:
        return "UNASSIGNED_179";
        break;
    case 180:
        return "UNASSIGNED_180";
        break;
    case 181:
        return "UNASSIGNED_181";
        break;
    case 182:
        return "UNASSIGNED_182";
        break;
    case 183:
        return "UNASSIGNED_183";
        break;
    case 184:
        return "UNASSIGNED_184";
        break;
    case 185:
        return "UNASSIGNED_185";
        break;
    case 186:
        return "UNASSIGNED_186";
        break;
    case 187:
        return "UNASSIGNED_187";
        break;
    case 188:
        return "UNASSIGNED_188";
        break;
    case 189:
        return "UNASSIGNED_189";
        break;
    case 190:
        return "UNASSIGNED_190";
        break;
    case 191:
        return "UNASSIGNED_191";
        break;
    case 192:
        return "UNASSIGNED_192";
        break;
    case 193:
        return "UNASSIGNED_193";
        break;
    case 194:
        return "UNASSIGNED_194";
        break;
    case 195:
        return "UNASSIGNED_195";
        break;
    case 196:
        return "UNASSIGNED_196";
        break;
    case 197:
        return "UNASSIGNED_197";
        break;
    case 198:
        return "UNASSIGNED_198";
        break;
    case 199:
        return "UNASSIGNED_199";
        break;
    case 200:
        return "UNASSIGNED_200";
        break;
    case 201:
        return "UNASSIGNED_201";
        break;
    case 202:
        return "UNASSIGNED_202";
        break;
    case 203:
        return "UNASSIGNED_203";
        break;
    case 204:
        return "UNASSIGNED_204";
        break;
    case 205:
        return "UNASSIGNED_205";
        break;
    case 206:
        return "UNASSIGNED_206";
        break;
    case 207:
        return "UNASSIGNED_207";
        break;
    case 208:
        return "UNASSIGNED_208";
        break;
    case 209:
        return "UNASSIGNED_209";
        break;
    case 210:
        return "UNASSIGNED_210";
        break;
    case 211:
        return "UNASSIGNED_211";
        break;
    case 212:
        return "UNASSIGNED_212";
        break;
    case 213:
        return "UNASSIGNED_213";
        break;
    case 214:
        return "UNASSIGNED_214";
        break;
    case 215:
        return "UNASSIGNED_215";
        break;
    case 216:
        return "UNASSIGNED_216";
        break;
    case 217:
        return "UNASSIGNED_217";
        break;
    case 218:
        return "UNASSIGNED_218";
        break;
    case 219:
        return "UNASSIGNED_219";
        break;
    case 220:
        return "UNASSIGNED_220";
        break;
    case 221:
        return "UNASSIGNED_221";
        break;
    case 222:
        return "UNASSIGNED_222";
        break;
    case 223:
        return "UNASSIGNED_223";
        break;
    case 224:
        return "UNASSIGNED_224";
        break;
    case 225:
        return "UNASSIGNED_225";
        break;
    case 226:
        return "UNASSIGNED_226";
        break;
    case 227:
        return "UNASSIGNED_227";
        break;
    case 228:
        return "UNASSIGNED_228";
        break;
    case 229:
        return "UNASSIGNED_229";
        break;
    case 230:
        return "UNASSIGNED_230";
        break;
    case 231:
        return "UNASSIGNED_231";
        break;
    case 232:
        return "UNASSIGNED_232";
        break;
    case 233:
        return "UNASSIGNED_233";
        break;
    case 234:
        return "UNASSIGNED_234";
        break;
    case 235:
        return "UNASSIGNED_235";
        break;
    case 236:
        return "UNASSIGNED_236";
        break;
    case 237:
        return "UNASSIGNED_237";
        break;
    case 238:
        return "UNASSIGNED_238";
        break;
    case 239:
        return "UNASSIGNED_239";
        break;
    case 240:
        return "UNASSIGNED_240";
        break;
    case 241:
        return "UNASSIGNED_241";
        break;
    case 242:
        return "UNASSIGNED_242";
        break;
    case 243:
        return "UNASSIGNED_243";
        break;
    case 244:
        return "UNASSIGNED_244";
        break;
    case 245:
        return "UNASSIGNED_245";
        break;
    case 246:
        return "UNASSIGNED_246";
        break;
    case 247:
        return "UNASSIGNED_247";
        break;
    case 248:
        return "UNASSIGNED_248";
        break;
    case 249:
        return "UNASSIGNED_249";
        break;
    case 250:
        return "UNASSIGNED_250";
        break;
    case 251:
        return "UNASSIGNED_251";
        break;
    case 252:
        return "UNASSIGNED_252";
        break;
    case 253:
        return "UNKNOWN_253";
        break;
    case 254:
        return "UNKNOWN_254";
        break;
    case 255:
        return "RESERVED";
        break;
    }
}

const char* get_ip_protocol_name(ip_protocol_t protocol) {
    switch (protocol) {
    case ip_protocol_t::HOPOPT:
        return "HOPOPT";
        break;
    case ip_protocol_t::ICMP:
        return "ICMP";
        break;
    case ip_protocol_t::IGMP:
        return "IGMP";
        break;
    case ip_protocol_t::GGP:
        return "GGP";
        break;
    case ip_protocol_t::IPV4:
        return "IPV4";
        break;
    case ip_protocol_t::ST:
        return "ST";
        break;
    case ip_protocol_t::TCP:
        return "TCP";
        break;
    case ip_protocol_t::CBT:
        return "CBT";
        break;
    case ip_protocol_t::EGP:
        return "EGP";
        break;
    case ip_protocol_t::IGP:
        return "IGP";
        break;
    case ip_protocol_t::BBN_RCC_MON:
        return "BBN_RCC_MON";
        break;
    case ip_protocol_t::NVP_II:
        return "NVP_II";
        break;
    case ip_protocol_t::PUP:
        return "PUP";
        break;
    case ip_protocol_t::ARGUS_DEPRECATED:
        return "ARGUS_DEPRECATED";
        break;
    case ip_protocol_t::EMCON:
        return "EMCON";
        break;
    case ip_protocol_t::XNET:
        return "XNET";
        break;
    case ip_protocol_t::CHAOS:
        return "CHAOS";
        break;
    case ip_protocol_t::UDP:
        return "UDP";
        break;
    case ip_protocol_t::MUX:
        return "MUX";
        break;
    case ip_protocol_t::DCN_MEAS:
        return "DCN_MEAS";
        break;
    case ip_protocol_t::HMP:
        return "HMP";
        break;
    case ip_protocol_t::PRM:
        return "PRM";
        break;
    case ip_protocol_t::XNS_IDP:
        return "XNS_IDP";
        break;
    case ip_protocol_t::TRUNK_1:
        return "TRUNK_1";
        break;
    case ip_protocol_t::TRUNK_2:
        return "TRUNK_2";
        break;
    case ip_protocol_t::LEAF_1:
        return "LEAF_1";
        break;
    case ip_protocol_t::LEAF_2:
        return "LEAF_2";
        break;
    case ip_protocol_t::RDP:
        return "RDP";
        break;
    case ip_protocol_t::IRTP:
        return "IRTP";
        break;
    case ip_protocol_t::ISO_TP4:
        return "ISO_TP4";
        break;
    case ip_protocol_t::NETBLT:
        return "NETBLT";
        break;
    case ip_protocol_t::MFE_NSP:
        return "MFE_NSP";
        break;
    case ip_protocol_t::MERIT_INP:
        return "MERIT_INP";
        break;
    case ip_protocol_t::DCCP:
        return "DCCP";
        break;
    case ip_protocol_t::THREEPC:
        return "THREEPC";
        break;
    case ip_protocol_t::IDPR:
        return "IDPR";
        break;
    case ip_protocol_t::XTP:
        return "XTP";
        break;
    case ip_protocol_t::DDP:
        return "DDP";
        break;
    case ip_protocol_t::IDPR_CMTP:
        return "IDPR_CMTP";
        break;
    case ip_protocol_t::TPPPPP:
        return "TPPPPP";
        break;
    case ip_protocol_t::IL:
        return "IL";
        break;
    case ip_protocol_t::IPV6:
        return "IPV6";
        break;
    case ip_protocol_t::SDRP:
        return "SDRP";
        break;
    case ip_protocol_t::IPV6_ROUTE:
        return "IPV6_ROUTE";
        break;
    case ip_protocol_t::IPV6_FRAG:
        return "IPV6_FRAG";
        break;
    case ip_protocol_t::IDRP:
        return "IDRP";
        break;
    case ip_protocol_t::RSVP:
        return "RSVP";
        break;
    case ip_protocol_t::GRE:
        return "GRE";
        break;
    case ip_protocol_t::DSR:
        return "DSR";
        break;
    case ip_protocol_t::BNA:
        return "BNA";
        break;
    case ip_protocol_t::ESP:
        return "ESP";
        break;
    case ip_protocol_t::AH:
        return "AH";
        break;
    case ip_protocol_t::I_NLSP:
        return "I_NLSP";
        break;
    case ip_protocol_t::SWIPE_DEPRECATED:
        return "SWIPE_DEPRECATED";
        break;
    case ip_protocol_t::NARP:
        return "NARP";
        break;
    case ip_protocol_t::MOBILE:
        return "MOBILE";
        break;
    case ip_protocol_t::TLSP:
        return "TLSP";
        break;
    case ip_protocol_t::SKIP:
        return "SKIP";
        break;
    case ip_protocol_t::IPV6_ICMP:
        return "IPV6_ICMP";
        break;
    case ip_protocol_t::IPV6_NONXT:
        return "IPV6_NONXT";
        break;
    case ip_protocol_t::IPV6_OPTS:
        return "IPV6_OPTS";
        break;
    case ip_protocol_t::UNKNOWN_61:
        return "UNKNOWN_61";
        break;
    case ip_protocol_t::CFTP:
        return "CFTP";
        break;
    case ip_protocol_t::UNKNOWN_63:
        return "UNKNOWN_63";
        break;
    case ip_protocol_t::SAT_EXPAK:
        return "SAT_EXPAK";
        break;
    case ip_protocol_t::KRYPTOLAN:
        return "KRYPTOLAN";
        break;
    case ip_protocol_t::RVD:
        return "RVD";
        break;
    case ip_protocol_t::IPPC:
        return "IPPC";
        break;
    case ip_protocol_t::UNKNOWN_68:
        return "UNKNOWN_68";
        break;
    case ip_protocol_t::SAT_MON:
        return "SAT_MON";
        break;
    case ip_protocol_t::VISA:
        return "VISA";
        break;
    case ip_protocol_t::IPCV:
        return "IPCV";
        break;
    case ip_protocol_t::CPNX:
        return "CPNX";
        break;
    case ip_protocol_t::CPHB:
        return "CPHB";
        break;
    case ip_protocol_t::WSN:
        return "WSN";
        break;
    case ip_protocol_t::PVP:
        return "PVP";
        break;
    case ip_protocol_t::BR_SAT_MON:
        return "BR_SAT_MON";
        break;
    case ip_protocol_t::SUN_ND:
        return "SUN_ND";
        break;
    case ip_protocol_t::WB_MON:
        return "WB_MON";
        break;
    case ip_protocol_t::WB_EXPAK:
        return "WB_EXPAK";
        break;
    case ip_protocol_t::ISO_IP:
        return "ISO_IP";
        break;
    case ip_protocol_t::VMTP:
        return "VMTP";
        break;
    case ip_protocol_t::SECURE_VMTP:
        return "SECURE_VMTP";
        break;
    case ip_protocol_t::VINES:
        return "VINES";
        break;
    case ip_protocol_t::IPTM_OR_TTP:
        return "IPTM_OR_TTP";
        break;
    case ip_protocol_t::NSFNET_IGP:
        return "NSFNET_IGP";
        break;
    case ip_protocol_t::DGP:
        return "DGP";
        break;
    case ip_protocol_t::TCF:
        return "TCF";
        break;
    case ip_protocol_t::EIGRP:
        return "EIGRP";
        break;
    case ip_protocol_t::OSPFIGP:
        return "OSPFIGP";
        break;
    case ip_protocol_t::SPRITE_RPC:
        return "SPRITE_RPC";
        break;
    case ip_protocol_t::LARP:
        return "LARP";
        break;
    case ip_protocol_t::MTP:
        return "MTP";
        break;
    case ip_protocol_t::AX_25:
        return "AX_25";
        break;
    case ip_protocol_t::IPIP:
        return "IPIP";
        break;
    case ip_protocol_t::MICP_DEPRECATED:
        return "MICP_DEPRECATED";
        break;
    case ip_protocol_t::SCC_SP:
        return "SCC_SP";
        break;
    case ip_protocol_t::ETHERIP:
        return "ETHERIP";
        break;
    case ip_protocol_t::ENCAP:
        return "ENCAP";
        break;
    case ip_protocol_t::UNKNOWN_99:
        return "UNKNOWN_99";
        break;
    case ip_protocol_t::GMTP:
        return "GMTP";
        break;
    case ip_protocol_t::IFMP:
        return "IFMP";
        break;
    case ip_protocol_t::PNNI:
        return "PNNI";
        break;
    case ip_protocol_t::PIM:
        return "PIM";
        break;
    case ip_protocol_t::ARIS:
        return "ARIS";
        break;
    case ip_protocol_t::SCPS:
        return "SCPS";
        break;
    case ip_protocol_t::QNX:
        return "QNX";
        break;
    case ip_protocol_t::A_N:
        return "A_N";
        break;
    case ip_protocol_t::IPCOMP:
        return "IPCOMP";
        break;
    case ip_protocol_t::SNP:
        return "SNP";
        break;
    case ip_protocol_t::COMPAQ_PEER:
        return "COMPAQ_PEER";
        break;
    case ip_protocol_t::IPX_IN_IP:
        return "IPX_IN_IP";
        break;
    case ip_protocol_t::VRRP:
        return "VRRP";
        break;
    case ip_protocol_t::PGM:
        return "PGM";
        break;
    case ip_protocol_t::UNKNOWN_114:
        return "UNKNOWN_114";
        break;
    case ip_protocol_t::L2TP:
        return "L2TP";
        break;
    case ip_protocol_t::DDX:
        return "DDX";
        break;
    case ip_protocol_t::IATP:
        return "IATP";
        break;
    case ip_protocol_t::STP:
        return "STP";
        break;
    case ip_protocol_t::SRP:
        return "SRP";
        break;
    case ip_protocol_t::UTI:
        return "UTI";
        break;
    case ip_protocol_t::SMP:
        return "SMP";
        break;
    case ip_protocol_t::SM_DEPRECATED:
        return "SM_DEPRECATED";
        break;
    case ip_protocol_t::PTP:
        return "PTP";
        break;
    case ip_protocol_t::ISISOVERIPV4:
        return "ISISOVERIPV4";
        break;
    case ip_protocol_t::FIRE:
        return "FIRE";
        break;
    case ip_protocol_t::CRTP:
        return "CRTP";
        break;
    case ip_protocol_t::CRUDP:
        return "CRUDP";
        break;
    case ip_protocol_t::SSCOPMCE:
        return "SSCOPMCE";
        break;
    case ip_protocol_t::IPLT:
        return "IPLT";
        break;
    case ip_protocol_t::SPS:
        return "SPS";
        break;
    case ip_protocol_t::PIPE:
        return "PIPE";
        break;
    case ip_protocol_t::SCTP:
        return "SCTP";
        break;
    case ip_protocol_t::FC:
        return "FC";
        break;
    case ip_protocol_t::RSVP_E2E_IGNORE:
        return "RSVP_E2E_IGNORE";
        break;
    case ip_protocol_t::MOBILITYHEADER:
        return "MOBILITYHEADER";
        break;
    case ip_protocol_t::UDPLITE:
        return "UDPLITE";
        break;
    case ip_protocol_t::MPLS_IN_IP:
        return "MPLS_IN_IP";
        break;
    case ip_protocol_t::MANET:
        return "MANET";
        break;
    case ip_protocol_t::HIP:
        return "HIP";
        break;
    case ip_protocol_t::SHIM6:
        return "SHIM6";
        break;
    case ip_protocol_t::WESP:
        return "WESP";
        break;
    case ip_protocol_t::ROHC:
        return "ROHC";
        break;
    case ip_protocol_t::ETHERNET:
        return "ETHERNET";
        break;
    case ip_protocol_t::UNASSIGNED_144:
        return "UNASSIGNED_144";
        break;
    case ip_protocol_t::UNASSIGNED_145:
        return "UNASSIGNED_145";
        break;
    case ip_protocol_t::UNASSIGNED_146:
        return "UNASSIGNED_146";
        break;
    case ip_protocol_t::UNASSIGNED_147:
        return "UNASSIGNED_147";
        break;
    case ip_protocol_t::UNASSIGNED_148:
        return "UNASSIGNED_148";
        break;
    case ip_protocol_t::UNASSIGNED_149:
        return "UNASSIGNED_149";
        break;
    case ip_protocol_t::UNASSIGNED_150:
        return "UNASSIGNED_150";
        break;
    case ip_protocol_t::UNASSIGNED_151:
        return "UNASSIGNED_151";
        break;
    case ip_protocol_t::UNASSIGNED_152:
        return "UNASSIGNED_152";
        break;
    case ip_protocol_t::UNASSIGNED_153:
        return "UNASSIGNED_153";
        break;
    case ip_protocol_t::UNASSIGNED_154:
        return "UNASSIGNED_154";
        break;
    case ip_protocol_t::UNASSIGNED_155:
        return "UNASSIGNED_155";
        break;
    case ip_protocol_t::UNASSIGNED_156:
        return "UNASSIGNED_156";
        break;
    case ip_protocol_t::UNASSIGNED_157:
        return "UNASSIGNED_157";
        break;
    case ip_protocol_t::UNASSIGNED_158:
        return "UNASSIGNED_158";
        break;
    case ip_protocol_t::UNASSIGNED_159:
        return "UNASSIGNED_159";
        break;
    case ip_protocol_t::UNASSIGNED_160:
        return "UNASSIGNED_160";
        break;
    case ip_protocol_t::UNASSIGNED_161:
        return "UNASSIGNED_161";
        break;
    case ip_protocol_t::UNASSIGNED_162:
        return "UNASSIGNED_162";
        break;
    case ip_protocol_t::UNASSIGNED_163:
        return "UNASSIGNED_163";
        break;
    case ip_protocol_t::UNASSIGNED_164:
        return "UNASSIGNED_164";
        break;
    case ip_protocol_t::UNASSIGNED_165:
        return "UNASSIGNED_165";
        break;
    case ip_protocol_t::UNASSIGNED_166:
        return "UNASSIGNED_166";
        break;
    case ip_protocol_t::UNASSIGNED_167:
        return "UNASSIGNED_167";
        break;
    case ip_protocol_t::UNASSIGNED_168:
        return "UNASSIGNED_168";
        break;
    case ip_protocol_t::UNASSIGNED_169:
        return "UNASSIGNED_169";
        break;
    case ip_protocol_t::UNASSIGNED_170:
        return "UNASSIGNED_170";
        break;
    case ip_protocol_t::UNASSIGNED_171:
        return "UNASSIGNED_171";
        break;
    case ip_protocol_t::UNASSIGNED_172:
        return "UNASSIGNED_172";
        break;
    case ip_protocol_t::UNASSIGNED_173:
        return "UNASSIGNED_173";
        break;
    case ip_protocol_t::UNASSIGNED_174:
        return "UNASSIGNED_174";
        break;
    case ip_protocol_t::UNASSIGNED_175:
        return "UNASSIGNED_175";
        break;
    case ip_protocol_t::UNASSIGNED_176:
        return "UNASSIGNED_176";
        break;
    case ip_protocol_t::UNASSIGNED_177:
        return "UNASSIGNED_177";
        break;
    case ip_protocol_t::UNASSIGNED_178:
        return "UNASSIGNED_178";
        break;
    case ip_protocol_t::UNASSIGNED_179:
        return "UNASSIGNED_179";
        break;
    case ip_protocol_t::UNASSIGNED_180:
        return "UNASSIGNED_180";
        break;
    case ip_protocol_t::UNASSIGNED_181:
        return "UNASSIGNED_181";
        break;
    case ip_protocol_t::UNASSIGNED_182:
        return "UNASSIGNED_182";
        break;
    case ip_protocol_t::UNASSIGNED_183:
        return "UNASSIGNED_183";
        break;
    case ip_protocol_t::UNASSIGNED_184:
        return "UNASSIGNED_184";
        break;
    case ip_protocol_t::UNASSIGNED_185:
        return "UNASSIGNED_185";
        break;
    case ip_protocol_t::UNASSIGNED_186:
        return "UNASSIGNED_186";
        break;
    case ip_protocol_t::UNASSIGNED_187:
        return "UNASSIGNED_187";
        break;
    case ip_protocol_t::UNASSIGNED_188:
        return "UNASSIGNED_188";
        break;
    case ip_protocol_t::UNASSIGNED_189:
        return "UNASSIGNED_189";
        break;
    case ip_protocol_t::UNASSIGNED_190:
        return "UNASSIGNED_190";
        break;
    case ip_protocol_t::UNASSIGNED_191:
        return "UNASSIGNED_191";
        break;
    case ip_protocol_t::UNASSIGNED_192:
        return "UNASSIGNED_192";
        break;
    case ip_protocol_t::UNASSIGNED_193:
        return "UNASSIGNED_193";
        break;
    case ip_protocol_t::UNASSIGNED_194:
        return "UNASSIGNED_194";
        break;
    case ip_protocol_t::UNASSIGNED_195:
        return "UNASSIGNED_195";
        break;
    case ip_protocol_t::UNASSIGNED_196:
        return "UNASSIGNED_196";
        break;
    case ip_protocol_t::UNASSIGNED_197:
        return "UNASSIGNED_197";
        break;
    case ip_protocol_t::UNASSIGNED_198:
        return "UNASSIGNED_198";
        break;
    case ip_protocol_t::UNASSIGNED_199:
        return "UNASSIGNED_199";
        break;
    case ip_protocol_t::UNASSIGNED_200:
        return "UNASSIGNED_200";
        break;
    case ip_protocol_t::UNASSIGNED_201:
        return "UNASSIGNED_201";
        break;
    case ip_protocol_t::UNASSIGNED_202:
        return "UNASSIGNED_202";
        break;
    case ip_protocol_t::UNASSIGNED_203:
        return "UNASSIGNED_203";
        break;
    case ip_protocol_t::UNASSIGNED_204:
        return "UNASSIGNED_204";
        break;
    case ip_protocol_t::UNASSIGNED_205:
        return "UNASSIGNED_205";
        break;
    case ip_protocol_t::UNASSIGNED_206:
        return "UNASSIGNED_206";
        break;
    case ip_protocol_t::UNASSIGNED_207:
        return "UNASSIGNED_207";
        break;
    case ip_protocol_t::UNASSIGNED_208:
        return "UNASSIGNED_208";
        break;
    case ip_protocol_t::UNASSIGNED_209:
        return "UNASSIGNED_209";
        break;
    case ip_protocol_t::UNASSIGNED_210:
        return "UNASSIGNED_210";
        break;
    case ip_protocol_t::UNASSIGNED_211:
        return "UNASSIGNED_211";
        break;
    case ip_protocol_t::UNASSIGNED_212:
        return "UNASSIGNED_212";
        break;
    case ip_protocol_t::UNASSIGNED_213:
        return "UNASSIGNED_213";
        break;
    case ip_protocol_t::UNASSIGNED_214:
        return "UNASSIGNED_214";
        break;
    case ip_protocol_t::UNASSIGNED_215:
        return "UNASSIGNED_215";
        break;
    case ip_protocol_t::UNASSIGNED_216:
        return "UNASSIGNED_216";
        break;
    case ip_protocol_t::UNASSIGNED_217:
        return "UNASSIGNED_217";
        break;
    case ip_protocol_t::UNASSIGNED_218:
        return "UNASSIGNED_218";
        break;
    case ip_protocol_t::UNASSIGNED_219:
        return "UNASSIGNED_219";
        break;
    case ip_protocol_t::UNASSIGNED_220:
        return "UNASSIGNED_220";
        break;
    case ip_protocol_t::UNASSIGNED_221:
        return "UNASSIGNED_221";
        break;
    case ip_protocol_t::UNASSIGNED_222:
        return "UNASSIGNED_222";
        break;
    case ip_protocol_t::UNASSIGNED_223:
        return "UNASSIGNED_223";
        break;
    case ip_protocol_t::UNASSIGNED_224:
        return "UNASSIGNED_224";
        break;
    case ip_protocol_t::UNASSIGNED_225:
        return "UNASSIGNED_225";
        break;
    case ip_protocol_t::UNASSIGNED_226:
        return "UNASSIGNED_226";
        break;
    case ip_protocol_t::UNASSIGNED_227:
        return "UNASSIGNED_227";
        break;
    case ip_protocol_t::UNASSIGNED_228:
        return "UNASSIGNED_228";
        break;
    case ip_protocol_t::UNASSIGNED_229:
        return "UNASSIGNED_229";
        break;
    case ip_protocol_t::UNASSIGNED_230:
        return "UNASSIGNED_230";
        break;
    case ip_protocol_t::UNASSIGNED_231:
        return "UNASSIGNED_231";
        break;
    case ip_protocol_t::UNASSIGNED_232:
        return "UNASSIGNED_232";
        break;
    case ip_protocol_t::UNASSIGNED_233:
        return "UNASSIGNED_233";
        break;
    case ip_protocol_t::UNASSIGNED_234:
        return "UNASSIGNED_234";
        break;
    case ip_protocol_t::UNASSIGNED_235:
        return "UNASSIGNED_235";
        break;
    case ip_protocol_t::UNASSIGNED_236:
        return "UNASSIGNED_236";
        break;
    case ip_protocol_t::UNASSIGNED_237:
        return "UNASSIGNED_237";
        break;
    case ip_protocol_t::UNASSIGNED_238:
        return "UNASSIGNED_238";
        break;
    case ip_protocol_t::UNASSIGNED_239:
        return "UNASSIGNED_239";
        break;
    case ip_protocol_t::UNASSIGNED_240:
        return "UNASSIGNED_240";
        break;
    case ip_protocol_t::UNASSIGNED_241:
        return "UNASSIGNED_241";
        break;
    case ip_protocol_t::UNASSIGNED_242:
        return "UNASSIGNED_242";
        break;
    case ip_protocol_t::UNASSIGNED_243:
        return "UNASSIGNED_243";
        break;
    case ip_protocol_t::UNASSIGNED_244:
        return "UNASSIGNED_244";
        break;
    case ip_protocol_t::UNASSIGNED_245:
        return "UNASSIGNED_245";
        break;
    case ip_protocol_t::UNASSIGNED_246:
        return "UNASSIGNED_246";
        break;
    case ip_protocol_t::UNASSIGNED_247:
        return "UNASSIGNED_247";
        break;
    case ip_protocol_t::UNASSIGNED_248:
        return "UNASSIGNED_248";
        break;
    case ip_protocol_t::UNASSIGNED_249:
        return "UNASSIGNED_249";
        break;
    case ip_protocol_t::UNASSIGNED_250:
        return "UNASSIGNED_250";
        break;
    case ip_protocol_t::UNASSIGNED_251:
        return "UNASSIGNED_251";
        break;
    case ip_protocol_t::UNASSIGNED_252:
        return "UNASSIGNED_252";
        break;
    case ip_protocol_t::UNKNOWN_253:
        return "UNKNOWN_253";
        break;
    case ip_protocol_t::UNKNOWN_254:
        return "UNKNOWN_254";
        break;
    case ip_protocol_t::RESERVED:
        return "RESERVED";
        break;
    }
}

bool read_protocol_from_string(const std::string& protocol_string, ip_protocol_t& ip_protocol_enum) {

    std::string protocol_string_lower = boost::algorithm::to_lower_copy(protocol_string);

    if (protocol_string_lower == "") {
        return false;
    } else if (protocol_string_lower == "hopopt") {
        ip_protocol_enum = ip_protocol_t::HOPOPT;
        return true;
    } else if (protocol_string_lower == "icmp") {
        ip_protocol_enum = ip_protocol_t::ICMP;
        return true;
    } else if (protocol_string_lower == "igmp") {
        ip_protocol_enum = ip_protocol_t::IGMP;
        return true;
    } else if (protocol_string_lower == "ggp") {
        ip_protocol_enum = ip_protocol_t::GGP;
        return true;
    } else if (protocol_string_lower == "ipv4") {
        ip_protocol_enum = ip_protocol_t::IPV4;
        return true;
    } else if (protocol_string_lower == "st") {
        ip_protocol_enum = ip_protocol_t::ST;
        return true;
    } else if (protocol_string_lower == "tcp") {
        ip_protocol_enum = ip_protocol_t::TCP;
        return true;
    } else if (protocol_string_lower == "cbt") {
        ip_protocol_enum = ip_protocol_t::CBT;
        return true;
    } else if (protocol_string_lower == "egp") {
        ip_protocol_enum = ip_protocol_t::EGP;
        return true;
    } else if (protocol_string_lower == "igp") {
        ip_protocol_enum = ip_protocol_t::IGP;
        return true;
    } else if (protocol_string_lower == "bbn_rcc_mon") {
        ip_protocol_enum = ip_protocol_t::BBN_RCC_MON;
        return true;
    } else if (protocol_string_lower == "nvp_ii") {
        ip_protocol_enum = ip_protocol_t::NVP_II;
        return true;
    } else if (protocol_string_lower == "pup") {
        ip_protocol_enum = ip_protocol_t::PUP;
        return true;
    } else if (protocol_string_lower == "argus_deprecated") {
        ip_protocol_enum = ip_protocol_t::ARGUS_DEPRECATED;
        return true;
    } else if (protocol_string_lower == "emcon") {
        ip_protocol_enum = ip_protocol_t::EMCON;
        return true;
    } else if (protocol_string_lower == "xnet") {
        ip_protocol_enum = ip_protocol_t::XNET;
        return true;
    } else if (protocol_string_lower == "chaos") {
        ip_protocol_enum = ip_protocol_t::CHAOS;
        return true;
    } else if (protocol_string_lower == "udp") {
        ip_protocol_enum = ip_protocol_t::UDP;
        return true;
    } else if (protocol_string_lower == "mux") {
        ip_protocol_enum = ip_protocol_t::MUX;
        return true;
    } else if (protocol_string_lower == "dcn_meas") {
        ip_protocol_enum = ip_protocol_t::DCN_MEAS;
        return true;
    } else if (protocol_string_lower == "hmp") {
        ip_protocol_enum = ip_protocol_t::HMP;
        return true;
    } else if (protocol_string_lower == "prm") {
        ip_protocol_enum = ip_protocol_t::PRM;
        return true;
    } else if (protocol_string_lower == "xns_idp") {
        ip_protocol_enum = ip_protocol_t::XNS_IDP;
        return true;
    } else if (protocol_string_lower == "trunk_1") {
        ip_protocol_enum = ip_protocol_t::TRUNK_1;
        return true;
    } else if (protocol_string_lower == "trunk_2") {
        ip_protocol_enum = ip_protocol_t::TRUNK_2;
        return true;
    } else if (protocol_string_lower == "leaf_1") {
        ip_protocol_enum = ip_protocol_t::LEAF_1;
        return true;
    } else if (protocol_string_lower == "leaf_2") {
        ip_protocol_enum = ip_protocol_t::LEAF_2;
        return true;
    } else if (protocol_string_lower == "rdp") {
        ip_protocol_enum = ip_protocol_t::RDP;
        return true;
    } else if (protocol_string_lower == "irtp") {
        ip_protocol_enum = ip_protocol_t::IRTP;
        return true;
    } else if (protocol_string_lower == "iso_tp4") {
        ip_protocol_enum = ip_protocol_t::ISO_TP4;
        return true;
    } else if (protocol_string_lower == "netblt") {
        ip_protocol_enum = ip_protocol_t::NETBLT;
        return true;
    } else if (protocol_string_lower == "mfe_nsp") {
        ip_protocol_enum = ip_protocol_t::MFE_NSP;
        return true;
    } else if (protocol_string_lower == "merit_inp") {
        ip_protocol_enum = ip_protocol_t::MERIT_INP;
        return true;
    } else if (protocol_string_lower == "dccp") {
        ip_protocol_enum = ip_protocol_t::DCCP;
        return true;
    } else if (protocol_string_lower == "threepc") {
        ip_protocol_enum = ip_protocol_t::THREEPC;
        return true;
    } else if (protocol_string_lower == "idpr") {
        ip_protocol_enum = ip_protocol_t::IDPR;
        return true;
    } else if (protocol_string_lower == "xtp") {
        ip_protocol_enum = ip_protocol_t::XTP;
        return true;
    } else if (protocol_string_lower == "ddp") {
        ip_protocol_enum = ip_protocol_t::DDP;
        return true;
    } else if (protocol_string_lower == "idpr_cmtp") {
        ip_protocol_enum = ip_protocol_t::IDPR_CMTP;
        return true;
    } else if (protocol_string_lower == "tppppp") {
        ip_protocol_enum = ip_protocol_t::TPPPPP;
        return true;
    } else if (protocol_string_lower == "il") {
        ip_protocol_enum = ip_protocol_t::IL;
        return true;
    } else if (protocol_string_lower == "ipv6") {
        ip_protocol_enum = ip_protocol_t::IPV6;
        return true;
    } else if (protocol_string_lower == "sdrp") {
        ip_protocol_enum = ip_protocol_t::SDRP;
        return true;
    } else if (protocol_string_lower == "ipv6_route") {
        ip_protocol_enum = ip_protocol_t::IPV6_ROUTE;
        return true;
    } else if (protocol_string_lower == "ipv6_frag") {
        ip_protocol_enum = ip_protocol_t::IPV6_FRAG;
        return true;
    } else if (protocol_string_lower == "idrp") {
        ip_protocol_enum = ip_protocol_t::IDRP;
        return true;
    } else if (protocol_string_lower == "rsvp") {
        ip_protocol_enum = ip_protocol_t::RSVP;
        return true;
    } else if (protocol_string_lower == "gre") {
        ip_protocol_enum = ip_protocol_t::GRE;
        return true;
    } else if (protocol_string_lower == "dsr") {
        ip_protocol_enum = ip_protocol_t::DSR;
        return true;
    } else if (protocol_string_lower == "bna") {
        ip_protocol_enum = ip_protocol_t::BNA;
        return true;
    } else if (protocol_string_lower == "esp") {
        ip_protocol_enum = ip_protocol_t::ESP;
        return true;
    } else if (protocol_string_lower == "ah") {
        ip_protocol_enum = ip_protocol_t::AH;
        return true;
    } else if (protocol_string_lower == "i_nlsp") {
        ip_protocol_enum = ip_protocol_t::I_NLSP;
        return true;
    } else if (protocol_string_lower == "swipe_deprecated") {
        ip_protocol_enum = ip_protocol_t::SWIPE_DEPRECATED;
        return true;
    } else if (protocol_string_lower == "narp") {
        ip_protocol_enum = ip_protocol_t::NARP;
        return true;
    } else if (protocol_string_lower == "mobile") {
        ip_protocol_enum = ip_protocol_t::MOBILE;
        return true;
    } else if (protocol_string_lower == "tlsp") {
        ip_protocol_enum = ip_protocol_t::TLSP;
        return true;
    } else if (protocol_string_lower == "skip") {
        ip_protocol_enum = ip_protocol_t::SKIP;
        return true;
    } else if (protocol_string_lower == "ipv6_icmp") {
        ip_protocol_enum = ip_protocol_t::IPV6_ICMP;
        return true;
    } else if (protocol_string_lower == "ipv6_nonxt") {
        ip_protocol_enum = ip_protocol_t::IPV6_NONXT;
        return true;
    } else if (protocol_string_lower == "ipv6_opts") {
        ip_protocol_enum = ip_protocol_t::IPV6_OPTS;
        return true;
    } else if (protocol_string_lower == "unknown_61") {
        ip_protocol_enum = ip_protocol_t::UNKNOWN_61;
        return true;
    } else if (protocol_string_lower == "cftp") {
        ip_protocol_enum = ip_protocol_t::CFTP;
        return true;
    } else if (protocol_string_lower == "unknown_63") {
        ip_protocol_enum = ip_protocol_t::UNKNOWN_63;
        return true;
    } else if (protocol_string_lower == "sat_expak") {
        ip_protocol_enum = ip_protocol_t::SAT_EXPAK;
        return true;
    } else if (protocol_string_lower == "kryptolan") {
        ip_protocol_enum = ip_protocol_t::KRYPTOLAN;
        return true;
    } else if (protocol_string_lower == "rvd") {
        ip_protocol_enum = ip_protocol_t::RVD;
        return true;
    } else if (protocol_string_lower == "ippc") {
        ip_protocol_enum = ip_protocol_t::IPPC;
        return true;
    } else if (protocol_string_lower == "unknown_68") {
        ip_protocol_enum = ip_protocol_t::UNKNOWN_68;
        return true;
    } else if (protocol_string_lower == "sat_mon") {
        ip_protocol_enum = ip_protocol_t::SAT_MON;
        return true;
    } else if (protocol_string_lower == "visa") {
        ip_protocol_enum = ip_protocol_t::VISA;
        return true;
    } else if (protocol_string_lower == "ipcv") {
        ip_protocol_enum = ip_protocol_t::IPCV;
        return true;
    } else if (protocol_string_lower == "cpnx") {
        ip_protocol_enum = ip_protocol_t::CPNX;
        return true;
    } else if (protocol_string_lower == "cphb") {
        ip_protocol_enum = ip_protocol_t::CPHB;
        return true;
    } else if (protocol_string_lower == "wsn") {
        ip_protocol_enum = ip_protocol_t::WSN;
        return true;
    } else if (protocol_string_lower == "pvp") {
        ip_protocol_enum = ip_protocol_t::PVP;
        return true;
    } else if (protocol_string_lower == "br_sat_mon") {
        ip_protocol_enum = ip_protocol_t::BR_SAT_MON;
        return true;
    } else if (protocol_string_lower == "sun_nd") {
        ip_protocol_enum = ip_protocol_t::SUN_ND;
        return true;
    } else if (protocol_string_lower == "wb_mon") {
        ip_protocol_enum = ip_protocol_t::WB_MON;
        return true;
    } else if (protocol_string_lower == "wb_expak") {
        ip_protocol_enum = ip_protocol_t::WB_EXPAK;
        return true;
    } else if (protocol_string_lower == "iso_ip") {
        ip_protocol_enum = ip_protocol_t::ISO_IP;
        return true;
    } else if (protocol_string_lower == "vmtp") {
        ip_protocol_enum = ip_protocol_t::VMTP;
        return true;
    } else if (protocol_string_lower == "secure_vmtp") {
        ip_protocol_enum = ip_protocol_t::SECURE_VMTP;
        return true;
    } else if (protocol_string_lower == "vines") {
        ip_protocol_enum = ip_protocol_t::VINES;
        return true;
    } else if (protocol_string_lower == "iptm_or_ttp") {
        ip_protocol_enum = ip_protocol_t::IPTM_OR_TTP;
        return true;
    } else if (protocol_string_lower == "nsfnet_igp") {
        ip_protocol_enum = ip_protocol_t::NSFNET_IGP;
        return true;
    } else if (protocol_string_lower == "dgp") {
        ip_protocol_enum = ip_protocol_t::DGP;
        return true;
    } else if (protocol_string_lower == "tcf") {
        ip_protocol_enum = ip_protocol_t::TCF;
        return true;
    } else if (protocol_string_lower == "eigrp") {
        ip_protocol_enum = ip_protocol_t::EIGRP;
        return true;
    } else if (protocol_string_lower == "ospfigp") {
        ip_protocol_enum = ip_protocol_t::OSPFIGP;
        return true;
    } else if (protocol_string_lower == "sprite_rpc") {
        ip_protocol_enum = ip_protocol_t::SPRITE_RPC;
        return true;
    } else if (protocol_string_lower == "larp") {
        ip_protocol_enum = ip_protocol_t::LARP;
        return true;
    } else if (protocol_string_lower == "mtp") {
        ip_protocol_enum = ip_protocol_t::MTP;
        return true;
    } else if (protocol_string_lower == "ax_25") {
        ip_protocol_enum = ip_protocol_t::AX_25;
        return true;
    } else if (protocol_string_lower == "ipip") {
        ip_protocol_enum = ip_protocol_t::IPIP;
        return true;
    } else if (protocol_string_lower == "micp_deprecated") {
        ip_protocol_enum = ip_protocol_t::MICP_DEPRECATED;
        return true;
    } else if (protocol_string_lower == "scc_sp") {
        ip_protocol_enum = ip_protocol_t::SCC_SP;
        return true;
    } else if (protocol_string_lower == "etherip") {
        ip_protocol_enum = ip_protocol_t::ETHERIP;
        return true;
    } else if (protocol_string_lower == "encap") {
        ip_protocol_enum = ip_protocol_t::ENCAP;
        return true;
    } else if (protocol_string_lower == "unknown_99") {
        ip_protocol_enum = ip_protocol_t::UNKNOWN_99;
        return true;
    } else if (protocol_string_lower == "gmtp") {
        ip_protocol_enum = ip_protocol_t::GMTP;
        return true;
    } else if (protocol_string_lower == "ifmp") {
        ip_protocol_enum = ip_protocol_t::IFMP;
        return true;
    } else if (protocol_string_lower == "pnni") {
        ip_protocol_enum = ip_protocol_t::PNNI;
        return true;
    } else if (protocol_string_lower == "pim") {
        ip_protocol_enum = ip_protocol_t::PIM;
        return true;
    } else if (protocol_string_lower == "aris") {
        ip_protocol_enum = ip_protocol_t::ARIS;
        return true;
    } else if (protocol_string_lower == "scps") {
        ip_protocol_enum = ip_protocol_t::SCPS;
        return true;
    } else if (protocol_string_lower == "qnx") {
        ip_protocol_enum = ip_protocol_t::QNX;
        return true;
    } else if (protocol_string_lower == "a_n") {
        ip_protocol_enum = ip_protocol_t::A_N;
        return true;
    } else if (protocol_string_lower == "ipcomp") {
        ip_protocol_enum = ip_protocol_t::IPCOMP;
        return true;
    } else if (protocol_string_lower == "snp") {
        ip_protocol_enum = ip_protocol_t::SNP;
        return true;
    } else if (protocol_string_lower == "compaq_peer") {
        ip_protocol_enum = ip_protocol_t::COMPAQ_PEER;
        return true;
    } else if (protocol_string_lower == "ipx_in_ip") {
        ip_protocol_enum = ip_protocol_t::IPX_IN_IP;
        return true;
    } else if (protocol_string_lower == "vrrp") {
        ip_protocol_enum = ip_protocol_t::VRRP;
        return true;
    } else if (protocol_string_lower == "pgm") {
        ip_protocol_enum = ip_protocol_t::PGM;
        return true;
    } else if (protocol_string_lower == "unknown_114") {
        ip_protocol_enum = ip_protocol_t::UNKNOWN_114;
        return true;
    } else if (protocol_string_lower == "l2tp") {
        ip_protocol_enum = ip_protocol_t::L2TP;
        return true;
    } else if (protocol_string_lower == "ddx") {
        ip_protocol_enum = ip_protocol_t::DDX;
        return true;
    } else if (protocol_string_lower == "iatp") {
        ip_protocol_enum = ip_protocol_t::IATP;
        return true;
    } else if (protocol_string_lower == "stp") {
        ip_protocol_enum = ip_protocol_t::STP;
        return true;
    } else if (protocol_string_lower == "srp") {
        ip_protocol_enum = ip_protocol_t::SRP;
        return true;
    } else if (protocol_string_lower == "uti") {
        ip_protocol_enum = ip_protocol_t::UTI;
        return true;
    } else if (protocol_string_lower == "smp") {
        ip_protocol_enum = ip_protocol_t::SMP;
        return true;
    } else if (protocol_string_lower == "sm_deprecated") {
        ip_protocol_enum = ip_protocol_t::SM_DEPRECATED;
        return true;
    } else if (protocol_string_lower == "ptp") {
        ip_protocol_enum = ip_protocol_t::PTP;
        return true;
    } else if (protocol_string_lower == "isisoveripv4") {
        ip_protocol_enum = ip_protocol_t::ISISOVERIPV4;
        return true;
    } else if (protocol_string_lower == "fire") {
        ip_protocol_enum = ip_protocol_t::FIRE;
        return true;
    } else if (protocol_string_lower == "crtp") {
        ip_protocol_enum = ip_protocol_t::CRTP;
        return true;
    } else if (protocol_string_lower == "crudp") {
        ip_protocol_enum = ip_protocol_t::CRUDP;
        return true;
    } else if (protocol_string_lower == "sscopmce") {
        ip_protocol_enum = ip_protocol_t::SSCOPMCE;
        return true;
    } else if (protocol_string_lower == "iplt") {
        ip_protocol_enum = ip_protocol_t::IPLT;
        return true;
    } else if (protocol_string_lower == "sps") {
        ip_protocol_enum = ip_protocol_t::SPS;
        return true;
    } else if (protocol_string_lower == "pipe") {
        ip_protocol_enum = ip_protocol_t::PIPE;
        return true;
    } else if (protocol_string_lower == "sctp") {
        ip_protocol_enum = ip_protocol_t::SCTP;
        return true;
    } else if (protocol_string_lower == "fc") {
        ip_protocol_enum = ip_protocol_t::FC;
        return true;
    } else if (protocol_string_lower == "rsvp_e2e_ignore") {
        ip_protocol_enum = ip_protocol_t::RSVP_E2E_IGNORE;
        return true;
    } else if (protocol_string_lower == "mobilityheader") {
        ip_protocol_enum = ip_protocol_t::MOBILITYHEADER;
        return true;
    } else if (protocol_string_lower == "udplite") {
        ip_protocol_enum = ip_protocol_t::UDPLITE;
        return true;
    } else if (protocol_string_lower == "mpls_in_ip") {
        ip_protocol_enum = ip_protocol_t::MPLS_IN_IP;
        return true;
    } else if (protocol_string_lower == "manet") {
        ip_protocol_enum = ip_protocol_t::MANET;
        return true;
    } else if (protocol_string_lower == "hip") {
        ip_protocol_enum = ip_protocol_t::HIP;
        return true;
    } else if (protocol_string_lower == "shim6") {
        ip_protocol_enum = ip_protocol_t::SHIM6;
        return true;
    } else if (protocol_string_lower == "wesp") {
        ip_protocol_enum = ip_protocol_t::WESP;
        return true;
    } else if (protocol_string_lower == "rohc") {
        ip_protocol_enum = ip_protocol_t::ROHC;
        return true;
    } else if (protocol_string_lower == "ethernet") {
        ip_protocol_enum = ip_protocol_t::ETHERNET;
        return true;
    } else if (protocol_string_lower == "unassigned_144") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_144;
        return true;
    } else if (protocol_string_lower == "unassigned_145") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_145;
        return true;
    } else if (protocol_string_lower == "unassigned_146") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_146;
        return true;
    } else if (protocol_string_lower == "unassigned_147") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_147;
        return true;
    } else if (protocol_string_lower == "unassigned_148") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_148;
        return true;
    } else if (protocol_string_lower == "unassigned_149") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_149;
        return true;
    } else if (protocol_string_lower == "unassigned_150") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_150;
        return true;
    } else if (protocol_string_lower == "unassigned_151") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_151;
        return true;
    } else if (protocol_string_lower == "unassigned_152") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_152;
        return true;
    } else if (protocol_string_lower == "unassigned_153") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_153;
        return true;
    } else if (protocol_string_lower == "unassigned_154") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_154;
        return true;
    } else if (protocol_string_lower == "unassigned_155") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_155;
        return true;
    } else if (protocol_string_lower == "unassigned_156") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_156;
        return true;
    } else if (protocol_string_lower == "unassigned_157") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_157;
        return true;
    } else if (protocol_string_lower == "unassigned_158") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_158;
        return true;
    } else if (protocol_string_lower == "unassigned_159") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_159;
        return true;
    } else if (protocol_string_lower == "unassigned_160") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_160;
        return true;
    } else if (protocol_string_lower == "unassigned_161") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_161;
        return true;
    } else if (protocol_string_lower == "unassigned_162") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_162;
        return true;
    } else if (protocol_string_lower == "unassigned_163") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_163;
        return true;
    } else if (protocol_string_lower == "unassigned_164") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_164;
        return true;
    } else if (protocol_string_lower == "unassigned_165") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_165;
        return true;
    } else if (protocol_string_lower == "unassigned_166") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_166;
        return true;
    } else if (protocol_string_lower == "unassigned_167") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_167;
        return true;
    } else if (protocol_string_lower == "unassigned_168") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_168;
        return true;
    } else if (protocol_string_lower == "unassigned_169") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_169;
        return true;
    } else if (protocol_string_lower == "unassigned_170") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_170;
        return true;
    } else if (protocol_string_lower == "unassigned_171") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_171;
        return true;
    } else if (protocol_string_lower == "unassigned_172") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_172;
        return true;
    } else if (protocol_string_lower == "unassigned_173") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_173;
        return true;
    } else if (protocol_string_lower == "unassigned_174") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_174;
        return true;
    } else if (protocol_string_lower == "unassigned_175") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_175;
        return true;
    } else if (protocol_string_lower == "unassigned_176") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_176;
        return true;
    } else if (protocol_string_lower == "unassigned_177") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_177;
        return true;
    } else if (protocol_string_lower == "unassigned_178") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_178;
        return true;
    } else if (protocol_string_lower == "unassigned_179") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_179;
        return true;
    } else if (protocol_string_lower == "unassigned_180") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_180;
        return true;
    } else if (protocol_string_lower == "unassigned_181") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_181;
        return true;
    } else if (protocol_string_lower == "unassigned_182") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_182;
        return true;
    } else if (protocol_string_lower == "unassigned_183") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_183;
        return true;
    } else if (protocol_string_lower == "unassigned_184") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_184;
        return true;
    } else if (protocol_string_lower == "unassigned_185") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_185;
        return true;
    } else if (protocol_string_lower == "unassigned_186") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_186;
        return true;
    } else if (protocol_string_lower == "unassigned_187") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_187;
        return true;
    } else if (protocol_string_lower == "unassigned_188") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_188;
        return true;
    } else if (protocol_string_lower == "unassigned_189") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_189;
        return true;
    } else if (protocol_string_lower == "unassigned_190") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_190;
        return true;
    } else if (protocol_string_lower == "unassigned_191") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_191;
        return true;
    } else if (protocol_string_lower == "unassigned_192") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_192;
        return true;
    } else if (protocol_string_lower == "unassigned_193") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_193;
        return true;
    } else if (protocol_string_lower == "unassigned_194") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_194;
        return true;
    } else if (protocol_string_lower == "unassigned_195") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_195;
        return true;
    } else if (protocol_string_lower == "unassigned_196") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_196;
        return true;
    } else if (protocol_string_lower == "unassigned_197") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_197;
        return true;
    } else if (protocol_string_lower == "unassigned_198") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_198;
        return true;
    } else if (protocol_string_lower == "unassigned_199") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_199;
        return true;
    } else if (protocol_string_lower == "unassigned_200") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_200;
        return true;
    } else if (protocol_string_lower == "unassigned_201") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_201;
        return true;
    } else if (protocol_string_lower == "unassigned_202") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_202;
        return true;
    } else if (protocol_string_lower == "unassigned_203") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_203;
        return true;
    } else if (protocol_string_lower == "unassigned_204") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_204;
        return true;
    } else if (protocol_string_lower == "unassigned_205") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_205;
        return true;
    } else if (protocol_string_lower == "unassigned_206") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_206;
        return true;
    } else if (protocol_string_lower == "unassigned_207") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_207;
        return true;
    } else if (protocol_string_lower == "unassigned_208") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_208;
        return true;
    } else if (protocol_string_lower == "unassigned_209") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_209;
        return true;
    } else if (protocol_string_lower == "unassigned_210") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_210;
        return true;
    } else if (protocol_string_lower == "unassigned_211") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_211;
        return true;
    } else if (protocol_string_lower == "unassigned_212") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_212;
        return true;
    } else if (protocol_string_lower == "unassigned_213") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_213;
        return true;
    } else if (protocol_string_lower == "unassigned_214") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_214;
        return true;
    } else if (protocol_string_lower == "unassigned_215") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_215;
        return true;
    } else if (protocol_string_lower == "unassigned_216") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_216;
        return true;
    } else if (protocol_string_lower == "unassigned_217") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_217;
        return true;
    } else if (protocol_string_lower == "unassigned_218") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_218;
        return true;
    } else if (protocol_string_lower == "unassigned_219") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_219;
        return true;
    } else if (protocol_string_lower == "unassigned_220") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_220;
        return true;
    } else if (protocol_string_lower == "unassigned_221") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_221;
        return true;
    } else if (protocol_string_lower == "unassigned_222") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_222;
        return true;
    } else if (protocol_string_lower == "unassigned_223") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_223;
        return true;
    } else if (protocol_string_lower == "unassigned_224") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_224;
        return true;
    } else if (protocol_string_lower == "unassigned_225") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_225;
        return true;
    } else if (protocol_string_lower == "unassigned_226") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_226;
        return true;
    } else if (protocol_string_lower == "unassigned_227") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_227;
        return true;
    } else if (protocol_string_lower == "unassigned_228") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_228;
        return true;
    } else if (protocol_string_lower == "unassigned_229") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_229;
        return true;
    } else if (protocol_string_lower == "unassigned_230") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_230;
        return true;
    } else if (protocol_string_lower == "unassigned_231") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_231;
        return true;
    } else if (protocol_string_lower == "unassigned_232") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_232;
        return true;
    } else if (protocol_string_lower == "unassigned_233") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_233;
        return true;
    } else if (protocol_string_lower == "unassigned_234") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_234;
        return true;
    } else if (protocol_string_lower == "unassigned_235") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_235;
        return true;
    } else if (protocol_string_lower == "unassigned_236") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_236;
        return true;
    } else if (protocol_string_lower == "unassigned_237") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_237;
        return true;
    } else if (protocol_string_lower == "unassigned_238") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_238;
        return true;
    } else if (protocol_string_lower == "unassigned_239") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_239;
        return true;
    } else if (protocol_string_lower == "unassigned_240") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_240;
        return true;
    } else if (protocol_string_lower == "unassigned_241") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_241;
        return true;
    } else if (protocol_string_lower == "unassigned_242") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_242;
        return true;
    } else if (protocol_string_lower == "unassigned_243") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_243;
        return true;
    } else if (protocol_string_lower == "unassigned_244") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_244;
        return true;
    } else if (protocol_string_lower == "unassigned_245") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_245;
        return true;
    } else if (protocol_string_lower == "unassigned_246") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_246;
        return true;
    } else if (protocol_string_lower == "unassigned_247") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_247;
        return true;
    } else if (protocol_string_lower == "unassigned_248") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_248;
        return true;
    } else if (protocol_string_lower == "unassigned_249") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_249;
        return true;
    } else if (protocol_string_lower == "unassigned_250") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_250;
        return true;
    } else if (protocol_string_lower == "unassigned_251") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_251;
        return true;
    } else if (protocol_string_lower == "unassigned_252") {
        ip_protocol_enum = ip_protocol_t::UNASSIGNED_252;
        return true;
    } else if (protocol_string_lower == "unknown_253") {
        ip_protocol_enum = ip_protocol_t::UNKNOWN_253;
        return true;
    } else if (protocol_string_lower == "unknown_254") {
        ip_protocol_enum = ip_protocol_t::UNKNOWN_254;
        return true;
    } else if (protocol_string_lower == "reserved") {
        ip_protocol_enum = ip_protocol_t::RESERVED;
        return true;
    } else {
        return false;
    }
}
ip_protocol_t get_ip_protocol_enum_type_from_integer(uint8_t protocol_as_integer) {
    return static_cast<ip_protocol_t>(protocol_as_integer);
}


uint8_t get_ip_protocol_enum_as_number(ip_protocol_t ip_protocol_enum) {
    return static_cast<std::underlying_type<ip_protocol_t>::type>(ip_protocol_enum);
}
