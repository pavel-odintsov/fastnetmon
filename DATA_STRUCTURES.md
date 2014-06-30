История использования структур была такой:
1) std::map
2) Так как предыдущий тормозил, решено было взять: unordered_map С++ 11
3) Но  std::unordered_map сегфолтился на пустом месте и был не особо стабилен: http://www.stableit.ru/2013/11/unorderedmap-c11-debian-wheezy.html
4) Мы вернулись на std::map
5) Но он тормозил и мы решили попробовать boost::unordered_map, он был быстр:

http://tinodidriksen.com/2009/07/09/cpp-map-speeds/

 standard map:         41% cpu in top
 boost::unordered_map: 25% cpu in top

Но он постоянно сегфолтился и оказывается не был совершенно thread safe:
http://boost.2283326.n4.nabble.com/boost-unordered-map-thread-safety-td2585435.html
http://meetingcpp.com/tl_files/2013/talks/Containers%20in%20Boost%20-%20Boris%20Schaeling.pdf

Стоит обратить внимание, что сегфолтился он как раз в итераторе, который читал данные, но писал их лишь из под mutex
6) Мы по-прежнему на std::map
