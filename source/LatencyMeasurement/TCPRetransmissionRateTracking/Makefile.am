noinst_LTLIBRARIES = libTcpRetransmissionTracker.la

libTcpRetransmissionTracker_la_SOURCES = tcp_retransmission_tracker.c
libTcpRetransmissionTracker_la_CPPFLAGS = -I$(srcdir)

check_PROGRAMS = tcp_retransmission_tracker_test
TESTS = tcp_retransmission_tracker_test

tcp_retransmission_tracker_test_SOURCES = $(top_srcdir)/source/test/tcp_retransmission_tracker_test.c
tcp_retransmission_tracker_test_CPPFLAGS = -I$(srcdir)
tcp_retransmission_tracker_test_LDADD = libTcpRetransmissionTracker.la
