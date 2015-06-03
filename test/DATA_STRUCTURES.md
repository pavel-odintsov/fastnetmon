The history of the use of the structures was:

* `std::map`
* As the previous slowed, it was decided to take: unordered_map in C++11
* But `std::unordered_map` segfault on empty space and was not very stable:  
  http://www.stableit.ru/2013/11/unorderedmap-c11-debian-wheezy.html
* We went back to `std::map`
* But he slowed down and we decided to try `boost::unordered_map`, [he was faster](http://tinodidriksen.com/2009/07/09/cpp-map-speeds/):

        standard map:         41% cpu in top
        boost::unordered_map: 25% cpu in top

But he constantly cellatica and it turns out was not completely thread safe:

* [boost::unordered_map thread safety](http://boost.2283326.n4.nabble.com/boost-unordered-map-thread-safety-td2585435.html)
* [Containers in Boost - 9 November 2013](http://meetingcpp.com/tl_files/2013/talks/Containers%20in%20Boost%20-%20Boris%20Schaeling.pdf)

It is worth to note that cellatica at the iterator that read data, but wrote them only under mutex

* We continue to `std::map`

###### What do we need?

We need a structure that will allow maximum speed and minimum loss of memory to store the integer value unsigned `32 bit` key. The key feature that it is in the range from about `zero` to `2^32`, but strictly and not sequentially continuous `50-100` blocks (different subnet).

The structure should provide the ability to work in multi-threaded mode in configuration - one writes and the other reads, with minimal use of locks.

Demands for speed ~ `1^-6` for recording.
