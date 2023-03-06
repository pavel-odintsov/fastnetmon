PORTNAME=	fastnetmon
PORTVERSION=	1.2.4
DISTVERSIONPREFIX=	v
CATEGORIES=	net-mgmt security

MAINTAINER=	farrokhi@FreeBSD.org
COMMENT=	Very fast DDoS analyzer with sflow/netflow/mirror support
WWW=		https://fastnetmon.com

LICENSE=	GPLv2
LICENSE_FILE=	${WRKSRC}/LICENSE

BROKEN_armv6=		does not build: invokes x86 assembler
BROKEN_armv7=		does not build: invokes x86 assembler

LIB_DEPENDS=	libboost_regex.so:devel/boost-libs \
		liblog4cpp.so:devel/log4cpp \
		libmongoc-1.0.so:devel/mongo-c-driver \
		libjson-c.so:devel/json-c \
		libbson-1.0.so:devel/libbson \
		libcapnp.so:devel/capnproto \
		libgrpc.so:devel/grpc142 \
		libprotobuf.so:devel/protobuf \
		libabsl_base.so:devel/abseil \
		libhiredis.so:databases/hiredis

USES=	cmake compiler:c++11-lang pkgconfig localbase:ldflags ssl

USE_GITHUB=	yes
GH_ACCOUNT=	pavel-odintsov

USERS=	${PORTNAME}
GROUPS=	${PORTNAME}

USE_RC_SUBR=	${PORTNAME}

OPTIONS_DEFINE=	DOCS REDIS

REDIS_LIB_DEPENDS=	libhiredis.so:databases/hiredis

PORTDOCS=	*

CXXFLAGS += -DBOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
CFLAGS_i386=	-march=i586
CMAKE_SOURCE_PATH=	${WRKSRC}/src
CMAKE_ARGS+=	-DDISABLE_PF_RING_SUPPORT=ON \
		-DENABLE_NETMAP_SUPPORT=OFF \
		-DLINK_WITH_ABSL=ON \
		-DSET_ABSOLUTE_INSTALL_PATH=OFF \
		-DCMAKE_INSTALL_MANDIR=${PREFIX}/man

CMAKE_INSTALL_PREFIX=	${PREFIX}

.include <bsd.port.pre.mk>

post-patch:
	@${REINPLACE_CMD} -e 's|/usr/local|${PREFIX}|; \
		s|/var/run|&/fastnetmon|g; s|/var/log|&/fastnetmon|g; \
		s|"/etc/|"${PREFIX}/etc/|g; s|/root/fastnetmon|${DATADIR}|g' \
		${WRKSRC}/src/fastnetmon.conf ${WRKSRC}/src/fastnetmon.cpp
	@${REINPLACE_CMD} -e 's|%%PREFIX%%|${PREFIX}|g' \
		${WRKSRC}/src/man/fastnetmon.8 ${WRKSRC}/src/fast_platform.h.template

post-install:
	${MV} ${STAGEDIR}${PREFIX}/etc/${PORTNAME}.conf \
		${STAGEDIR}${PREFIX}/etc/${PORTNAME}.conf.sample
	${MKDIR} ${STAGEDIR}/var/run/fastnetmon ${STAGEDIR}/var/log/fastnetmon
	${INSTALL_SCRIPT} ${WRKSRC}/src/notify_about_attack.sh ${STAGEDIR}${PREFIX}/bin

post-install-DOCS-on:
	cd ${WRKSRC} && ${COPYTREE_SHARE} "README.md docs" ${STAGEDIR}${DOCSDIR}

.include <bsd.port.post.mk>
