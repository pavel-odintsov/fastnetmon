/***************************************************************************
 *   Copyright (C) 2004-2011 by Patrick Audley                             *
 *   paudley@blackcat.ca                                                   *
 *   http://patrickaudley.com                                              *
 *                                                                         *
 ***************************************************************************/
/**
 * @file lru_cache.cpp Template cache with an LRU removal policy (unit tests)
 * @author Patrick Audley
*/
#include "lru_cache.h"

#ifdef UNITTEST
#include "unit_test.h"
#include <string>
#include <stdlib.h>

/// LRUCache type for use in the unit tests
typedef LRUCache<std::string,std::string> unit_lru_type;
/// LRUCache POD type for use in the unit tests
typedef LRUCache<int,int> unit_lru_type2;
/// Data class for testing the scoping issues with const refs
class test_big_data {
	public:
		char buffer[1000];
};
/// LRUCache with large data for use in the unit tests
typedef LRUCache<int,test_big_data> unit_lru_type3;

/// Dumps the cache for debugging.
std::string dump( unit_lru_type *L ) {
	unit_lru_type::Key_List _list( L->get_all_keys() );
	std::string ret("");
	for( unit_lru_type::Key_List_Iter liter = _list.begin(); liter != _list.end(); liter++ ) {
		ret.append( *liter );
		ret.append( ":" );
		ret.append( L->fetch( *liter, false ) );
		ret.append( "\n" );
	}
	//std::cout << "Dump--" << std::endl << ret << "----" << std::endl;
	return ret;
}

/// Scoping test object
unit_lru_type3* L3;

UNIT_TEST_DEFINES

/** @test Basic creation and desctruction test */
DEFINE_TEST( lru_cache_1cycle ) {
	const std::string unit_data_1cycle_a("foo:4\n");
	const std::string unit_data_1cycle_b("bar:flower\nfoo:4\n");
	const std::string unit_data_1cycle_c("foo:4\nbar:flower\n");
	const std::string unit_data_1cycle_d("foo:moose\nbaz:Stalin\nbar:flower\n");
	const std::string unit_data_1cycle_e("foo:moose\nbar:flower\n");
	const std::string unit_data_1cycle_f("quz:xyzzy\nbaz:monkey\nfoo:moose\n");
	const std::string unit_data_1cycle_g("coat:mouse\npants:cat\nsocks:bear\n");

	unit_lru_type *L = new unit_lru_type(3);
	unit_assert( "size==0", (L->size() == 0) );
	unit_assert( "maxsize==3", (L->max_size() == 3) );

	// Checking a bogus key shouldn't alter the cache.
	L->exists( "foo" );
	unit_assert( "exists() doesn't increase size", (L->size() == 0) );

	// Check insert() and exists()
	L->insert( "foo", "4" );
	unit_assert( "size==1 after insert(foo,4)", (L->size() == 1) );
	unit_assert( "check exists(foo)", L->exists( "foo" ) );
	unit_assert( "contents check a)", unit_data_1cycle_a.compare( dump( L ) ) == 0 );

	// Check second insert and ordering
	L->insert( "bar", "flower" );
	unit_assert( "size==2 after insert(bar,flower)", (L->size() == 2) );
	unit_assert( "contents check b)", unit_data_1cycle_b.compare( dump( L ) ) == 0 );

	// Check touching
	L->touch( "foo" );
	unit_assert( "contents check c)", unit_data_1cycle_c.compare( dump( L ) ) == 0 );

	// Insert of an existing element should result in only a touch
	L->insert( "bar", "flower" );
	unit_assert( "verify insert touches", unit_data_1cycle_b.compare( dump( L ) ) == 0 );

	// Verify that fetch works
	unit_assert( "verify fetch(bar)", ( std::string("flower").compare( L->fetch("bar") ) == 0 ) );

	// Insert of an existing element with new data should replace and touch
	L->insert( "baz", "Stalin" );
	L->insert( "foo", "moose" );
	unit_assert( "verify insert replaces", unit_data_1cycle_d.compare( dump( L ) ) == 0 );

	// Test removal of an existing member.
	L->remove( "baz" );
	unit_assert( "verify remove works", unit_data_1cycle_e.compare( dump( L ) ) == 0 );

	// Test LRU removal as we add more members than max_size()
	L->insert( "baz", "monkey" );
	L->insert( "quz", "xyzzy" );
	unit_assert( "verify LRU semantics", unit_data_1cycle_f.compare( dump( L ) ) == 0 );

	// Stress test the implementation a little..
	const char *names[10] = { "moose", "dog", "bear", "cat", "mouse", "hat", "mittens", "socks", "pants", "coat" };
	for( int i = 0; i < 50; i++ ) {
		L->insert( names[ i % 10 ], names[ i % 9 ] );
	}
	unit_assert( "stress test a little", unit_data_1cycle_g.compare( dump( L ) ) == 0 );

	// Setup a little for the third test which verifies that scoped references inserted into the cache don't disappear.
	L3 = new unit_lru_type3(2);
	for( int i = 0; i < 10; i++ ) {
		test_big_data B;
		snprintf( B.buffer, 1000, "%d\n", i );
		L3->insert( i, B );
	}

        // Check that clear fully clears.
        //   Bug discovered by:  月迷津渡 gdcex@qq.com
        unit_assert( "very size before clear.", (L->size() > 0) );
        L->clear();
        unit_assert( "very size after clear.", (L->size() == 0) );

	unit_pass();
}

#define TRANSACTIONS 50000
/** @test Insert lots of objects and benchmark the rate. */
DEFINE_TEST( lru_cache_stress ) {
	// Stress test the implementation a little more using no objects
	unit_lru_type2 *L2 = new unit_lru_type2(5);
	double t0 = cputime();
	for( int i = 0; i < TRANSACTIONS; i++ ) {
		L2->insert( i, i-1 );
	}
	double t1 = cputime();
	delete L2;
	print_cputime( "(int,int) inserts", t1-t0, TRANSACTIONS );
	unit_pass();
}

/** @test Check that objects inserted in a different scope are still there. */
DEFINE_TEST( lru_cache_scope_check ) {
	test_big_data* B = L3->fetch_ptr( 9 );
	unit_assert( "scope check element L3[1]", ( strncmp( B->buffer, "9\n", 1000 ) == 0 ) );
	B = L3->fetch_ptr( 8 );
	unit_assert( "scope check element L3[2]", ( strncmp( B->buffer, "8\n", 1000 ) == 0 ) );
	delete L3;
	unit_pass();
}

#ifdef _REENTRANT
#include <boost/thread/thread.hpp>

#define THREAD_TRANS 20000
#define THREAD_COUNT 10

unit_lru_type2 *L4;

void insert_junk(){
	for( int i = 0; i < THREAD_TRANS; i++ ) {
		L4->insert( i, i+1 );
		L4->remove( i-5 );
		L4->fetch( i-3 );
		L4->touch( i-10 );
	}
}

/** @test Check for badness with multithreaded access, this is more of a stress test than an empirical test. */
DEFINE_TEST( lru_cache_threads ) {
	L4 = new unit_lru_type2( 20 );
	boost::thread_group thrds;
	double t0 = cputime();
	for (int i=0; i < THREAD_COUNT; ++i)
		thrds.create_thread(&insert_junk);
	thrds.join_all();
	double t1 = cputime();
	print_cputime( "(int,int) multithreaded inserts", t1-t0, THREAD_TRANS*THREAD_COUNT*4 );
	delete L4;
	unit_pass();
}

#endif

UNIT_TEST_RUN( "LRU Cache" );
	ADD_TEST( lru_cache_1cycle );
	ADD_TEST( lru_cache_stress );
	ADD_TEST( lru_cache_scope_check );
#ifdef _REENTRANT
	ADD_TEST( lru_cache_threads );
#endif
UNIT_TEST_END;

#endif
