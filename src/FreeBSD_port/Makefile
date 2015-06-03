# $FreeBSD$

PORTNAME=	fastnetmon
PORTVERSION=	1.1.2
DISTVERSIONPREFIX=	v
CATEGORIES=	net-mgmt

MAINTAINER=	pavel.odintsov@gmail.com
COMMENT=	Very fast DDoS analyzer with sFlow/NetFLow/IPFIX/SPAN/mirror support

LICENSE=	GPLv2
LICENSE_FILE=	${WRKSRC}/LICENSE

LIB_DEPENDS=	liblog4cpp.so:${PORTSDIR}/devel/log4cpp \
		libboost_regex.so:${PORTSDIR}/devel/boost-libs

USE_GITHUB=	yes
GH_ACCOUNT=	FastVPSEestiOu

# TODO: enable this after updating /usr/ports/{UIDs,GIDs}
#USERS=		fastnetmon
#GROUPS=		fastnetmon

USES=		cmake
CMAKE_SOURCE_PATH=${WRKSRC}/src

USE_RC_SUBR=	fastnetmon

PORTDOCS=	*

OPTIONS_DEFINE=	DOCS

post-patch:
	@${REINPLACE_CMD} -e 's|/usr/local|${LOCALBASE}|' ${WRKSRC}/src/CMakeLists.txt
	@${REINPLACE_CMD} -e 's|/usr/local|${PREFIX}|; \
		s|/var/run|&/fastnetmon|g; s|/var/log|&/fastnetmon|g; \
		s|"/etc/|"${PREFIX}/etc/|g; s|/root/fastnetmon|${DATADIR}|g' \
		${WRKSRC}/src/fastnetmon.conf ${WRKSRC}/src/fastnetmon.cpp

post-install:
	${MV} ${STAGEDIR}${PREFIX}/etc/${PORTNAME}.conf \
		${STAGEDIR}${PREFIX}/etc/${PORTNAME}.conf.sample
	cd ${WRKSRC} && ${COPYTREE_SHARE} "README.md docs" ${STAGEDIR}${DOCSDIR}
	${MKDIR} ${STAGEDIR}/var/run/fastnetmon ${STAGEDIR}/var/log/fastnetmon

.include <bsd.port.mk>
