#include <iostream>
#include <queue>
#include <cstdlib>
#include <list>
#include <algorithm>
#include <vector>

bool compare_min(unsigned int a, unsigned int b) {
    return a > b;
}


bool compare_max(unsigned int a, unsigned int b) {
    return a < b;
}

template <class order_by_template_type> class fast_priority_queue {
    public:
    fast_priority_queue(unsigned int queue_size) {
        this->queue_size = queue_size;
        internal_list.reserve(queue_size);
    }
    void insert(order_by_template_type main_value, int data) {
        // Because it's ehap we can remove

        // Append new element to the end of list
        internal_list.push_back(main_value);

        // Convert list to the complete heap
        // Up to logarithmic in the distance between first and last: Compares elements and
        // potentially swaps (or moves) them until rearranged as a longer heap.
        std::push_heap(internal_list.begin(), internal_list.end(), compare_min);

        if (this->internal_list.size() >= queue_size) {
            // And now we should remove minimal element from the internal_list
            // Prepare heap to remove min element
            std::pop_heap(internal_list.begin(), internal_list.end(), compare_min);
            // Remove element from the head
            internal_list.pop_back();
        }
    }
    order_by_template_type get_min_element() {
        // We will return head of list because it's consists minimum element
        return internal_list.front();
    }
    void print_internal_list() {
        for (unsigned int i = 0; i < internal_list.size(); i++) {
            std::cout << internal_list[i] << std::endl;
        }
    }
    void print() {
        // Create new list for sort because we can't do it in place
        std::vector<order_by_template_type> sorted_list;

        // Allocate enough space
        sorted_list.reserve(internal_list.size());

        // Copy to new vector with copy constructor
        sorted_list = internal_list;

        // Execute heap sort because array paritally sorted already
        std::sort_heap(sorted_list.begin(), sorted_list.end(), compare_min);

        for (unsigned int i = 0; i < sorted_list.size(); i++) {
            std::cout << sorted_list[i] << std::endl;
        }
    }

    private:
    order_by_template_type max_number;
    order_by_template_type min_number;
    unsigned int queue_size;
    // We can't use list here!
    std::vector<order_by_template_type> internal_list;
    // std::priority_queue<int, std::list<int>, std::less<int> > class_priority_queue;
};


int main() {
    fast_priority_queue<unsigned int> my_priority_queue(10);

    for (int i = 0; i < 100; i++) {
        int current_value = rand() % 100;
        // std::cout<<current_value<<std::endl;

        if (current_value > my_priority_queue.get_min_element()) {
            // Check for existence of this element in struct already
            my_priority_queue.insert(current_value, 0);
        }
    }

    std::cout << "Print internal list" << std::endl;
    my_priority_queue.print_internal_list();

    std::cout << "Print sorted list" << std::endl;
    my_priority_queue.print();
}
