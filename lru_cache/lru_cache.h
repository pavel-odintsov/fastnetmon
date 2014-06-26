/***************************************************************************
 *   Copyright (C) 2004-2011 by Patrick Audley                             *
 *   paudley@blackcat.ca                                                   *
 *   http://patrickaudley.com                                              *
 *                                                                         *
 ***************************************************************************/
/**
 * @file lru_cache.h Template cache with an LRU removal policy
 * @author Patrick Audley
 * @version 1.4
 * @date June 2012
 * @par
 * This cache is thread safe if compiled with _REENTRANT defined.  It
 * uses the BOOST scientific computing library to provide the thread safety
 * mutexes.
 *
 * @par
 * Thanks to graydon@pobox.com for the size counting functor.
 * Thanks to 月迷津渡 gdcex@qq.com for fixes and tweaks.
 *
 */
/**
 * @mainpage LRU Cache
 *
 * @section intro_section Introduction
 * 
 * Fast, thread safe C++ template with Least Recently Used (LRU)
 * removal semantics. Complete with a comprehensive unit test
 * suite. Threading features require the BOOST scientific library to be
 * installed.
 * 
 * @section usage_section Usage
 * 
 * An LRU cache is a fixed size cache that discards the oldest (least
 * recently accessed) elements after it fills up.  It's ideally
 * suited to be used in situations where you need to speed up access to
 * slower data sources (databases, synthetic structures, etc.). Below is
 * a simple example of using it to cache strings using integer keys.
 * 
 * @section also_section See Also
 *
 * See: <a href="http://patrickaudley.com/code/project/lrucache">LRU Cache</a>
 *
 * @example lru_example.cpp
 */
#include <map>
#include <list>
#include <vector>
#ifdef _REENTRANT
#include <boost/thread/mutex.hpp>
/// If we are reentrant then use a BOOST scoped mutex where neccessary.
#define SCOPED_MUTEX  boost::mutex::scoped_lock lock(this->_mutex);
#else
/// If we aren't reentrant then don't do anything.
#define SCOPED_MUTEX
#endif

template < class T >
struct Countfn {
		unsigned long operator()( const T &x ) { return 1; }
};


/**
 * @brief Template cache with an LRU removal policy.
 * @class LRUCache
 *
 * @par
 * This template creats a simple collection of key-value pairs that grows
 * until the size specified at construction is reached and then begins
 * discard the Least Recently Used element on each insertion.
 *
 */
template< class Key, class Data, class Sizefn = Countfn< Data > > class LRUCache {
	public:
		typedef std::list< std::pair< Key, Data > > List;         ///< Main cache storage typedef
		typedef typename List::iterator List_Iter;                ///< Main cache iterator
		typedef typename List::const_iterator List_cIter;         ///< Main cache iterator (const)
		typedef std::vector< Key > Key_List;                      ///< List of keys
		typedef typename Key_List::iterator Key_List_Iter;        ///< Main cache iterator
		typedef typename Key_List::const_iterator Key_List_cIter; ///< Main cache iterator (const)
		typedef std::map< Key, List_Iter > Map;                   ///< Index typedef
		typedef std::pair< Key, List_Iter > Pair;                 ///< Pair of Map elements
		typedef typename Map::iterator Map_Iter;			            ///< Index iterator
		typedef typename Map::const_iterator Map_cIter;           ///< Index iterator (const)

	private:
		List _list;               ///< Main cache storage
		Map _index;               ///< Cache storage index
		unsigned long _max_size;  ///< Maximum abstract size of the cache
		unsigned long _curr_size; ///< Current abstract size of the cache

#ifdef _REENTRANT
		boost::mutex _mutex;
#endif

	public:

		/** @brief Creates a cache that holds at most Size worth of elements.
		 *  @param Size maximum size of cache
		 */
		LRUCache( const unsigned long Size ) :
				_max_size( Size ),
				_curr_size( 0 )
				{}

		/// Destructor - cleans up both index and storage
		~LRUCache() { clear(); }

		/** @brief Gets the current abstract size of the cache.
		 *  @return current size
 		 */
		inline const unsigned long size( void ) const { return _curr_size; }

		/** @brief Gets the maximum sbstract size of the cache.
		 *  @return maximum size
		 */
		inline const unsigned long max_size( void ) const { return _max_size; }

		/// Clears all storage and indices.
		void clear( void ) {
			SCOPED_MUTEX;
			_list.clear();
			_index.clear();
			_curr_size = 0;
		};

		/** @brief Checks for the existance of a key in the cache.
		 *  @param key to check for
		 *  @return bool indicating whether or not the key was found.
		 */
#ifdef _REENTRANT
		inline bool exists( const Key &key ) {
			SCOPED_MUTEX;
#else
		inline bool exists( const Key &key ) const {
#endif
			return _index.find( key ) != _index.end();
		}

		/** @brief Removes a key-data pair from the cache.
		 *  @param key to be removed
		 */
		inline void remove( const Key &key ) {
#ifdef _REENTRANT
			SCOPED_MUTEX;
#endif
			Map_Iter miter = _index.find( key );
			if( miter == _index.end() ) return;
			_remove( miter );
		}

		/** @brief Touches a key in the Cache and makes it the most recently used.
		 *  @param key to be touched
		 */
		inline void touch( const Key &key ) {
			SCOPED_MUTEX;
			_touch( key );
		}

		/** @brief Fetches a pointer to cache data.
		 *  @param key to fetch data for
		 *  @param touch whether or not to touch the data
		 *  @return pointer to data or NULL on error
		 */
		inline Data *fetch_ptr( const Key &key, bool touch = true ) {
			SCOPED_MUTEX;
			Map_Iter miter = _index.find( key );
			if( miter == _index.end() ) return NULL;
			_touch( key );
			return &(miter->second->second);
		}

		/** @brief Fetches a copy of cached data.
		 *  @param key to fetch data for
		 *  @param touch_data whether or not to touch the data
		 *  @return copy of the data or an empty Data object if not found
		 */
		inline Data fetch( const Key &key, bool touch_data = true ) {
			SCOPED_MUTEX;
			Map_Iter miter = _index.find( key );
			if( miter == _index.end() )
				return Data();
			Data tmp = miter->second->second;
			if( touch_data )
				_touch( key );
			return tmp;
		}

		/** @brief Fetches a pointer to cache data.
		 *  @param key to fetch data for
		 *  @param data to fetch data into
		 *  @param touch_data whether or not to touch the data
		 *  @return whether or not data was filled in
		 */
		inline bool fetch( const Key &key, Data &data, bool touch_data = true ) {
			SCOPED_MUTEX;
			Map_Iter miter = _index.find( key );
			if( miter == _index.end() ) return false;
			if( touch_data )
			  _list.splice( _list.begin(), _list, miter->second ); // Do a touch inline.
			data = miter->second->second;
			return true;
		}

		/** @brief Inserts a key-data pair into the cache and removes entries if neccessary.
		 *  @param key object key for insertion
		 *  @param data object data for insertion
		 *  @note This function checks key existance and touches the key if it already exists.
		 */
		inline void insert( const Key &key, const Data &data ) {
			SCOPED_MUTEX;
			// Touch the key, if it exists, then replace the content.
			Map_Iter miter = _touch( key );
			if( miter != _index.end() )
				_remove( miter );

			// Ok, do the actual insert at the head of the list
			_list.push_front( std::make_pair( key, data ) );
			List_Iter liter = _list.begin();

			// Store the index
			_index.insert( std::make_pair( key, liter ) );
			_curr_size += Sizefn()( data );

			// Check to see if we need to remove an element due to exceeding max_size
			while( _curr_size > _max_size ) {
				// Remove the last element.
				liter = _list.end();
				--liter;
				_remove( liter->first );
			}
		}

		/** @brief Get a list of keys.
				@return list of the current keys.
		*/
		inline const Key_List get_all_keys( void ) {
			SCOPED_MUTEX;
			Key_List ret;
			for( List_cIter liter = _list.begin(); liter != _list.end(); liter++ )
				ret.push_back( liter->first );
			return ret;
		}

	private:
		/** @brief Internal touch function.
		 *  @param key to be touched
		 *  @return a Map_Iter pointing to the key that was touched.
		 */
		inline Map_Iter _touch( const Key &key ) {
			Map_Iter miter = _index.find( key );
			if( miter == _index.end() ) return miter;
			// Move the found node to the head of the list.
			_list.splice( _list.begin(), _list, miter->second );
			return miter;
		}

		/** @brief Interal remove function
		 *  @param miter Map_Iter that points to the key to remove
		 *  @warning miter is now longer usable after being passed to this function.
		 */
		inline void _remove( const Map_Iter &miter ) {
			_curr_size -= Sizefn()( miter->second->second );
			_list.erase( miter->second );
			_index.erase( miter );
		}

		/** @brief Interal remove function
		 *  @param key to remove
		 */
		inline void _remove( const Key &key ) {
			Map_Iter miter = _index.find( key );
			_remove( miter );
		}
};
