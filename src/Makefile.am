bin_PROGRAMS = captool flowpacketconverter encrypt

if STATIC
noinst_LTLIBRARIES = \
	libcaptool.la
else
lib_LTLIBRARIES = \
	libcaptool.la \
	libClassAssigner.la \
	libClassifierDispatcher.la \
	libDPI.la \
	libETH.la \
	libFlowOutput.la \
	libFlowOutputStrict.la \
	libFlowPacket.la \
	libGTPControl.la \
	libGTPUser.la \
	libHTTP.la \
	libFilter.la \
	libIP.la \
	libLinuxCookedHeader.la \
	libPcapCapture.la \
	libPcapOutput.la \
	libPortClassifier.la \
	libIPRangeClassifier.la \
	libIPTransportClassifier.la \
	libSequenceNumberClassifier.la \
	libServerPortSearch.la \
	libP2PHostSearch.la \
	libSummarizer.la \
	libTCP.la \
	libUDP.la \
	libP2PHeuristics.la
endif

AUTOMAKE_OPTIONS = subdir-objects

EXTRA_DIST = doc

###
### Global settings
###

all_extra_ldflags = $(extralibs_LIBS) $(BOOST_LDFLAGS) $(BOOST_ASIO_LIB)

AM_CPPFLAGS = $(BOOST_CPPFLAGS)
AM_CXXFLAGS = -D CAPTOOL_LOG_LEVEL=800 $(extralibs_CFLAGS) -std=c++0x
# LDFLAGS defaults are good for the module libraries;  we override LDFLAGS in programs individually
AM_LDFLAGS = $(all_extra_ldflags) -avoid-version
if STATIC
AM_LDFLAGS += $(extra_static_libs)
endif
LDADD = libcaptool.la

# NB: PROFILE implies STATIC !
if STATIC
AM_CXXFLAGS += -D CAPTOOL_STATIC_BUILD
endif

if DEBUG
AM_CXXFLAGS += -Wall -Wextra -g -O0 -fno-inline #these dump core in ~list :( -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -D_GLIBCXX_CONCEPT_CHECKS -D_GLIBCXX_ASSERT
else
AM_CXXFLAGS += -g -O2
endif

if PROFILE
if PROFILE_PERFTOOLS
AM_CXXFLAGS += -D CAPTOOL_PROFILE_PERFTOOLS
else
AM_CXXFLAGS += -pg
endif
else
if ! STATIC
AM_LDFLAGS += -module -version-info 1  # TODO aggree on interface numbering
endif
endif

###
### Per target settings
###

captool_SOURCES = Captool.cpp Captool.h
captool_CXXFLAGS = $(AM_CXXFLAGS) -U CAPTOOL_LOG_LEVEL -D CAPTOOL_LOG_LEVEL=700
captool_LDFLAGS = $(all_extra_ldflags)
if STATIC
captool_SOURCES += $(all_module_sources)
captool_LDFLAGS += -all-static $(extra_static_libs)
captool_CXXFLAGS += -U CAPTOOL_LOG_LEVEL -D CAPTOOL_LOG_LEVEL=800
endif

flowpacketconverter_SOURCES = tools/FlowPacketConverter.cpp tools/FlowPacketConverter.h
flowpacketconverter_CXXFLAGS = $(AM_CXXFLAGS)
flowpacketconverter_LDFLAGS = $(all_extra_ldflags)
if STATIC
flowpacketconverter_SOURCES += $(all_module_sources) # quick fix to make it compile for now
flowpacketconverter_LDFLAGS += -all-static $(extra_static_libs)
else
flowpacketconverter_SOURCES += modules/flowpacket/FlowPacket.cpp
endif

encrypt_SOURCES = tools/encrypt.cpp util/crypt.h
encrypt_LDFLAGS = $(all_extra_ldflags)
if STATIC
encrypt_LDFLAGS += -all-static
endif

# FIXME duplicate listing is ugly :(
all_module_sources = \
	$(libcaptool_la_SOURCES) \
	$(libClassAssigner_la_SOURCES) \
	$(libClassifierDispatcher_la_SOURCES) \
	$(libDPI_la_SOURCES) \
	$(libETH_la_SOURCES) \
	$(libFlowOutput_la_SOURCES) \
	$(libFlowOutputStrict_la_SOURCES) \
	$(libFlowPacket_la_SOURCES) \
	$(libGTPControl_la_SOURCES) \
	$(libGTPUser_la_SOURCES) \
	$(libHTTP_la_SOURCES) \
	$(libFilter_la_SOURCES) \
	$(libIP_la_SOURCES) \
	$(libLinuxCookedHeader_la_SOURCES) \
	$(libPcapCapture_la_SOURCES) \
	$(libPcapOutput_la_SOURCES) \
	$(libPortClassifier_la_SOURCES) \
	$(libIPRangeClassifier_la_SOURCES) \
	$(libIPTransportClassifier_la_SOURCES) \
	$(libSequenceNumberClassifier_la_SOURCES) \
	$(libServerPortSearch_la_SOURCES) \
	$(libP2PHostSearch_la_SOURCES) \
	$(libSummarizer_la_SOURCES) \
	$(libTCP_la_SOURCES) \
	$(libUDP_la_SOURCES) \
	$(libP2PHeuristics_la_SOURCES)

libcaptool_la_SOURCES = \
	captoolpacket/CaptoolPacket.cpp captoolpacket/CaptoolPacket.h captoolpacket/CaptoolPacketProtocol.h \
	\
	classification/ClassificationMetadata.cpp classification/ClassificationMetadata.h classification/ClassifierDescriptor.h classification/ClassificationBlock.h classification/Signature.h \
	classification/Classifier.cpp classification/Classifier.h \
	classification/FacetClassified.cpp classification/FacetClassified.h \
	classification/Hintable.cpp classification/Hintable.h \
	classification/IdNameMapper.cpp classification/IdNameMapper.h \
	classification/TagContainer.cpp classification/TagContainer.h \
	\
	filemanager/FileManager.cpp filemanager/FileManager.h filemanager/FileGenerator.h \
	\
	flow/BasicFlow.cpp flow/BasicFlow.h \
	flow/Flow.cpp flow/Flow.h flow/ParametersContainer.h \
	flow/FlowID.cpp flow/FlowID.h flow/FlowIDEquals.h flow/FlowIDEqualsStrict.h flow/FlowIDHasher.h \
	flow/OptionsContainer.cpp flow/OptionsContainer.h \
	flow/PacketStatistics.cpp flow/PacketStatistics.h \
	flow/StatFlow.cpp flow/StatFlow.h \
	\
	userid/ID.cpp userid/ID.h userid/TBCD.cpp userid/TBCD.h userid/IMSI.cpp userid/IMSI.h userid/IMEISV.cpp userid/IMEISV.h userid/MACAddress.h userid/MACAddress.cpp \
	ip/IPAddress.cpp ip/IPAddress.h \
	\
	modulemanager/activemodule/ActiveModule.cpp modulemanager/activemodule/ActiveModuleListener.h modulemanager/activemodule/ActiveModule.h \
	modulemanager/Module.cpp modulemanager/Module.h \
	modulemanager/ModuleLibrary.cpp modulemanager/ModuleLibrary.h \
	modulemanager/ModuleManager.cpp modulemanager/ModuleManager.h modulemanager/NullModule.h \
	\
	util/Configurable.h util/ObjectPool.h util/RefCounter.h util/AutoMem.h util/Hash.h util/poolable.h util/log.h util/Timestamped.h util/TimeSortedList.h util/crypt.h util/kernel_control.h
	
libClassAssigner_la_SOURCES = modules/classifiers/ClassAssigner.cpp modules/classifiers/ClassAssigner.h modules/classifiers/ClassificationConstraints.cpp modules/classifiers/ClassificationConstraints.h

libClassifierDispatcher_la_SOURCES = modules/classifiers/ClassifierDispatcher.cpp modules/classifiers/ClassifierDispatcher.h

libDPI_la_SOURCES = modules/classifiers/DPI.cpp modules/classifiers/DPI.h

libETH_la_SOURCES = modules/eth/ETH.cpp modules/eth/ETH.h

libFlowOutput_la_SOURCES = modules/flowoutput/FlowOutput.cpp modules/flowoutput/FlowOutput.h modules/flowoutput/FlowList.h modules/flowoutput/FlowModule.h

libFlowOutputStrict_la_SOURCES = modules/flowoutput/FlowOutputStrict.cpp modules/flowoutput/FlowOutputStrict.h
libFlowOutputStrict_la_LIBADD = libFlowOutput.la

libFlowPacket_la_SOURCES = modules/flowpacket/FlowPacket.cpp modules/flowpacket/FlowPacketFileStruct.h modules/flowpacket/FlowPacket.h

libGTPControl_la_SOURCES = \
	modules/gtpcontrol/GTPControl.cpp modules/gtpcontrol/GTPControl.h \
	modules/gtpcontrol/GTPInformationElements.cpp modules/gtpcontrol/GTPInformationElements.h \
	modules/gtpcontrol/PDPConnection.cpp modules/gtpcontrol/PDPConnection.h modules/gtpcontrol/PDPConnectionEquals.h modules/gtpcontrol/PDPConnectionHasher.h \
	modules/gtpcontrol/PDPConnections.cpp modules/gtpcontrol/PDPConnections.h \
	modules/gtpcontrol/PDPContext.cpp modules/gtpcontrol/PDPContext.h modules/gtpcontrol/PDPContextStatus.h \
	modules/gtpcontrol/gtp.h

libGTPUser_la_SOURCES = modules/gtpuser/GTPUser.cpp modules/gtpuser/GTPUser.h

libHTTP_la_SOURCES = modules/http/HTTP.cpp modules/http/HTTP.h

libFilter_la_SOURCES = \
	modules/filter/Filter.cpp modules/filter/Filter.h \
	modules/filter/UserFilterProcessor.h \
	modules/filter/TacFilterProcessor.h \
	modules/filter/FilterProcessor.h \
	modules/filter/PortFilterProcessor.h \
	modules/filter/SamplingFilterProcessor.h \
	modules/filter/IPRangeFilterProcessor.h

libIP_la_SOURCES = \
	modules/ip/IP.cpp modules/ip/IP.h \
	modules/ip/IPFragmentHole.cpp modules/ip/IPFragmentHole.h \
	modules/ip/IPFragments.cpp modules/ip/IPFragments.h \
	modules/ip/IPFragmentsID.cpp modules/ip/IPFragmentsID.h

libLinuxCookedHeader_la_SOURCES = modules/eth/LinuxCookedHeader.cpp modules/eth/LinuxCookedHeader.h modules/eth/sll.h

libPcapCapture_la_SOURCES = modules/pcapcapture/PcapCapture.cpp modules/pcapcapture/PcapCapture.h

libPcapOutput_la_SOURCES = modules/pcapoutput/PcapOutput.cpp modules/pcapoutput/PcapOutput.h

libPortClassifier_la_SOURCES = modules/classifiers/PortClassifier.cpp  modules/classifiers/PortClassifier.h
libPortClassifier_la_LDFLAGS = $(AM_LDFLAGS) -lm

libIPRangeClassifier_la_SOURCES = modules/classifiers/IPRangeClassifier.cpp  modules/classifiers/IPRangeClassifier.h

libIPTransportClassifier_la_SOURCES = modules/classifiers/IPTransportClassifier.cpp  modules/classifiers/IPTransportClassifier.h

libSequenceNumberClassifier_la_SOURCES = modules/classifiers/SequenceNumberClassifier.cpp modules/classifiers/SequenceNumberClassifier.h modules/classifiers/SequenceNumberData.h

libServerPortSearch_la_SOURCES = modules/classifiers/ServerPortSearch.cpp modules/classifiers/ServerPortSearch.h

libP2PHostSearch_la_SOURCES = modules/classifiers/P2PHostSearch.cpp modules/classifiers/P2PHostSearch.h

libSummarizer_la_SOURCES = modules/summary/Summarizer.cpp modules/summary/Summarizer.h

libTCP_la_SOURCES = modules/tcp/TCP.cpp modules/tcp/TCP.h

libUDP_la_SOURCES = modules/udp/UDP.cpp modules/udp/UDP.h

libP2PHeuristics_la_SOURCES = flowmodules/P2PHeuristics.cpp flowmodules/P2PHeuristics.h
