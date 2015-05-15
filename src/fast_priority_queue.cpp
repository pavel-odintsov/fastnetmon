bool compare_min(unsigned int a, unsigned int b) {
    return a > b;
}

bool compare_max(unsigned int a, unsigned int b) {
    return a < b;
}

template <class order_by_template_type>
fast_priority_queue<order_by_template_type>::fast_priority_queue(unsigned int queue_size) {
    this->queue_size = queue_size;
    internal_list.reserve(queue_size);
}

template <class order_by_template_type>
void fast_priority_queue<order_by_template_type>::insert(order_by_template_type main_value, int data) {
    // Because it's ehap we can remove

    // Append new element to the end of list
    internal_list.push_back(main_value);

    // Convert list to the complete heap
    // Up to logarithmic in the distance between first and last: Compares elements and potentially
    // swaps (or moves) them until rearranged as a longer heap.
    std::push_heap(internal_list.begin(), internal_list.end(), compare_min);

    if (this->internal_list.size() >= queue_size) {
        // And now we should remove minimal element from the internal_list
        // Prepare heap to remove min element
        std::pop_heap(internal_list.begin(), internal_list.end(), compare_min);
        // Remove element from the head
        internal_list.pop_back();
    }
}

template <class order_by_template_type>
order_by_template_type fast_priority_queue<order_by_template_type>::get_min_element() {
    // We will return head of list because it's consists minimum element
    return internal_list.front();
}

template <class order_by_template_type>
void fast_priority_queue<order_by_template_type>::print_internal_list() {
    for (unsigned int i = 0; i < internal_list.size(); i++) {
        std::cout << internal_list[i] << std::endl;
    }
}

template <class order_by_template_type> void fast_priority_queue<order_by_template_type>::print() {
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
