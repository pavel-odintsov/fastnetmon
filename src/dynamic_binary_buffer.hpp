#pragma once

#include <iostream>

class dynamic_binary_buffer_t {
    public:
    dynamic_binary_buffer_t() : byte_storage(nullptr), maximum_internal_storage_size(0) {
        // std::cout << "Default constructor called" << std::endl;
    }

    // Explicitly removed it as we need to implement it properly when needed
    dynamic_binary_buffer_t(dynamic_binary_buffer_t&& that) = delete;

    // We should set maximum buffer size here.
    // TODO: add ability to relocate memory of we need more memory
    bool set_maximum_buffer_size_in_bytes(ssize_t size) {
        // Already allocated
        if (byte_storage) {
            return false;
        }

        // With nothrow we are using new without exceptions
        byte_storage = new (std::nothrow) uint8_t[size];

        if (byte_storage) {
            maximum_internal_storage_size = size;
            return true;
        } else {
            return false;
        }
    }

    ~dynamic_binary_buffer_t() {
        // std::cout << "Destructor called" << std::endl;

        if (byte_storage) {
            delete[] byte_storage;
            byte_storage                  = nullptr;
            maximum_internal_storage_size = 0;
        }
    }

    // So this implementation will be useful only for real object copies
    // For returning local variable from function compiler will do this job
    // perfectly:
    // https://en.wikipedia.org/wiki/Return_value_optimization
    dynamic_binary_buffer_t(const dynamic_binary_buffer_t& that) {
        this->maximum_internal_storage_size = that.maximum_internal_storage_size;

        // Copy internal pointer too! It's very important!
        this->internal_data_shift = that.internal_data_shift;

        // std::cout << "Copy constructor called" << std::endl;

        // std::cout << "Copy constructor will copy " << this->internal_size << "
        // bytes" <<
        // std::endl;

        // We are copying all memory (unused too)
        if (this->maximum_internal_storage_size > 0) {
            // Allocate memory for new instance
            this->set_maximum_buffer_size_in_bytes(this->maximum_internal_storage_size);

            memcpy(this->byte_storage, that.byte_storage, that.maximum_internal_storage_size);
        }
    }

    // All this functions just append some data with certain length to buffer and
    // increase total
    // size
    // They are very similar to std::stringstream but for binary data only

    bool append_byte(uint8_t byte_value) {
        // Do bounds check
        if (internal_data_shift > maximum_internal_storage_size - 1) {
            errors_occured = true;
            return false;
        }

        byte_storage[internal_data_shift] = byte_value;
        internal_data_shift += sizeof(uint8_t);
        return true;
    }

    // Use reference as argument
    bool append_dynamic_buffer(dynamic_binary_buffer_t& dynamic_binary_buffer) {
        // In this case we are copying only used memory
        // TODO: Why +1?
        if (internal_data_shift + dynamic_binary_buffer.get_used_size() > maximum_internal_storage_size + 1) {
            errors_occured = true;
            return false;
        }

        return this->append_data_as_pointer(dynamic_binary_buffer.get_pointer(), dynamic_binary_buffer.get_used_size());
    }

    bool append_data_as_pointer(const void* ptr, size_t length) {
        if (internal_data_shift + length > maximum_internal_storage_size + 1) {
            errors_occured = true;
            return false;
        }

        memcpy(byte_storage + internal_data_shift, ptr, length);
        internal_data_shift += length;
        return true;
    }

    template <typename src_type> bool append_data_as_object_ptr(src_type* ptr) {
        if (internal_data_shift + sizeof(src_type) > maximum_internal_storage_size + 1) {
            errors_occured = true;
            return false;
        }

        memcpy(byte_storage + internal_data_shift, ptr, sizeof(src_type));
        internal_data_shift += sizeof(src_type);

        return true;
    }

    // All functions below DO NOT CHANGE internal buffer position! They are very
    // low level and
    // should be avoided!

    // We could set arbitrary byte with this function
    bool set_byte(uint32_t byte_number, uint8_t byte_value) {
        // Do bounds check
        if (byte_number > maximum_internal_storage_size - 1) {
            errors_occured = true;
            return false;
        }

        byte_storage[byte_number] = byte_value;
        return true;
    }

    bool memcpy_from_ptr(uint32_t shift, const void* ptr, uint32_t length) {
        if (shift + length > maximum_internal_storage_size + 1) {
            errors_occured = true;
            return false;
        }

        memcpy(byte_storage + shift, ptr, length);
        return true;
    }

    // More user friendly version of previous function
    template <typename src_type> bool memcpy_from_object_ptr(uint32_t shift, src_type* ptr) {
        if (shift + sizeof(src_type) > maximum_internal_storage_size + 1) {
            errors_occured = true;
            return false;
        }

        memcpy(byte_storage + shift, ptr, sizeof(src_type));
        return true;
    }

    // Return full size (with non initialized data region too)
    uint32_t get_full_size() {
        return maximum_internal_storage_size;
    }

    // Return only used memory region
    size_t get_used_size() {
        return internal_data_shift;
    }

    const uint8_t* get_pointer() {
        return byte_storage;
    }

    // If we have any issues with it
    bool is_failed() {
        return errors_occured;
    }

    private:
    size_t internal_data_shift            = 0;
    uint8_t* byte_storage                 = nullptr;
    ssize_t maximum_internal_storage_size = 0;
    // If any errors occurred in any time when we used this buffer
    bool errors_occured = false;
};
