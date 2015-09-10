#include <json-c/json.h>
#include <stdio.h>

int main() {
    for (int i = 0; i < 10000000; i++) {
        json_object * jobj = json_object_new_object();

        /*Creating a json array*/
        json_object *jarray = json_object_new_array();

        /*Creating json strings*/
        json_object *jstring1 = json_object_new_string("c");
        json_object *jstring2 = json_object_new_string("c++");
        json_object *jstring3 = json_object_new_string("php");

        /*Adding the above created json strings to the array*/
        json_object_array_add(jarray,jstring1);
        json_object_array_add(jarray,jstring2);
        json_object_array_add(jarray,jstring3);

        json_object_object_add(jobj, "languages", jarray);

        // After _array_add and _object_add operations all ownership moves to obj and will be freed up with jobj

        /*Now printing the json object*/
        //printf ("The json object created: %sn", json_object_to_json_string(jobj));
    
        // Free up memory
        json_object_put(jobj);
    }
}
