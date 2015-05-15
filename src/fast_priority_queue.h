#ifndef fast_priority_queue_h
#define fast_priority_queue_h

#include <iostream>
#include <queue>
#include <cstdlib>
#include <list>
#include <algorithm>
#include <vector>

template <class order_by_template_type> class fast_priority_queue {
    public:
    fast_priority_queue(unsigned int queue_size);
    void insert(order_by_template_type main_value, int data);
    order_by_template_type get_min_element();
    void print_internal_list();
    void print();

    private:
    order_by_template_type max_number;
    order_by_template_type min_number;
    unsigned int queue_size;
    // We can't use list here!
    std::vector<order_by_template_type> internal_list;
    // std::priority_queue<int, std::list<int>, std::less<int> > class_priority_queue;
};

#include "fast_priority_queue.cpp"

#endif
