// Этот код не используется, но почти работоспособен. Нужно для быстрой проверки принадлежности пакета диапазонам провайдера
/*
void insert_prefix_bitwise_tree(tree_leaf* root, string subnet, int cidr_mask) {
   uint32_t netmask_as_int = convert_ip_as_string_to_uint(subnet);

    //std::cout<<std::bitset<32>(netmask_as_int)<<endl;

    // ntogl: network byte order to host, htonl - наоборот
    netmask_as_int = ntohl(netmask_as_int);

    // intruduce temporary pointer
    tree_leaf* temp_root = root;

    // интерируем по значимым битам сети, остальные игнорируем, они нас не интересуют
    for (int i= 31; i >= 32 - cidr_mask; i--) {
        uint32_t result_bit = netmask_as_int & (1 << i);
        bool bit = result_bit == 0 ? false : true;
        //cout<<"Insert: "<<bit<<" from position "<<i<<endl;      
 
        // условимся, что слева - нули, справа - единицы

        // теперь индекс может быть, а может и отсутствовать, смотрим мы только дочерние листья корня, корень не трогаем
        if (bit) {
            // проверяем правое поддерево
            if (temp_root->right != NULL)  {
                // ок, элемент уже есть, просто переключаем указатель
                temp_root = temp_root->right;
            } else {
                // элемента нету, его нужно создать
                tree_leaf* new_leaf = new tree_leaf;
                new_leaf->right = new_leaf->left = NULL;
                new_leaf->bit = bit;

                temp_root->right = new_leaf;

                temp_root = new_leaf;
            }    
       
        } else {
            // проверим левое поддерево
            if (temp_root->left != NULL)  { 
                // ок, элемент уже есть, просто переключаем указатель на левый
                temp_root = temp_root->left;
            } else {
                // элемента нету, его нужно создать
                tree_leaf* new_leaf = new tree_leaf;
                new_leaf->right = new_leaf->left = NULL;
                new_leaf->bit = bit;
    
                temp_root->left = new_leaf;

                temp_root = new_leaf;
            } 
        }
    }

    // #include <bitset>
    // std::cout<<bitset<32>(netmask_as_int)<<endl;
}
*/

/*
bool belongs_to_networks(tree_leaf* root, uint32_t ip) {
    // introduce temporary pointer
    tree_leaf* temp_root = root;

    // Blank tree or tree with only root is blank, we can't find nothing in it
    if (temp_root == NULL or ( temp_root->left == NULL && temp_root->right == NULL) ) {
        return false;
    }

    // convert to host byte order
    ip = ntohl(ip);

    int bits_matched = 0;
    for (int i= 31; i >= 0; i--) {
        uint32_t result_bit = ip & (1 << i);
        bool bit = result_bit == 0 ? false : true;

        // Текущий узел - терминальный
        if ( (temp_root->left == NULL && temp_root->right == NULL)) {
            if (bits_matched > 0) {
                // если более дочерних элементов нету (узел терминальный!) и совпадение хотя бы с одним битом - мы нашли маску
                return true;
            } else {
                // обход кончился и мы ничего не нашли
                return false;
            }
        }

        if (bit) {
            // смотрим правое поддерево
            if (temp_root->right != NULL) {
                // идем далее
                temp_root = temp_root->right;
                bits_matched++;
            } else {
                // справа ничего нету, но может быть слева
                if (temp_root->left != NULL) {
                    return false;
                } else {
                    // рассмотрено выше
                }
            }
        } else {
            if (temp_root->left != NULL) {
                // идем влево
                temp_root = temp_root->left;
                bits_matched++;
            } else {
                // слева ничего нету, но может быть спарва
                if (temp_root->right != NULL) {
                    return false;
                } else {
                    // рассмотрено выше
                }
            }  
        }

    }

    // это повтор аналогичной проверки в начале цикла, но это требуется, так как мы можем пройти цикл и не налететь на вариант, что мы достигли терминала - оба потомка стали нулл
    if ( (temp_root->left == NULL && temp_root->right == NULL)) {
        if (bits_matched > 0) {
            // если более дочерних элементов нету (узел терминальный!) и совпадение хотя бы с одним битом - мы нашли маску
            //std::cout<<"Bits matched: "<<bits_matched<<endl;
            return true;
        } else {
            // обход кончился и мы ничего не нашли
            return false;
        }
    }

    // This point must not achieved in any cases! 
    return false; 
}

