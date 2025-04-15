extern "C" {
#define USE_C_INTERFACE 1
#include <osv/device.h>
#include <osv/prex.h>
#include <osv/vnode.h>
#include <osv/mount.h>
#include <osv/debug.h>
#include <osv/file.h>
#include <osv/vnode_attr.h>

void* alloc_contiguous_aligned(size_t size, size_t align);
void free_contiguous_aligned(void* p);
}

#include "lucafs.hh"
#include "tree.h"
#include <ext4_errno.h>
#include <ext4_dir.h>
#include <ext4_inode.h>
#include <ext4_fs.h>
#include <ext4_dir_idx.h>
#include <ext4_trans.h>

#include <cstdlib>
#include <time.h>
#include <cstddef>

#include <algorithm>
#include <stdio.h>

#include <unordered_map>

std::unordered_map<uint64_t, cache_node_t*> cache_map;

std::unordered_map<uint64_t, cache_node_t*> dirty_map;

int is_queue_empty(cache_queue_t *queue)
{
    return queue->size == 0;
}

int is_queue_full(cache_queue_t *queue)
{
    return queue->size == queue->max_size;
}

cache_node_t *allocate_node(cache_queue_t *queue) {
    memory_pool_t *pool = queue->pool;
    if (!pool->free_list) {
        printf("allocate_node: pool->free_list is NULL\n");
        return NULL;  // 内存池已空
    }

    cache_node_t *node = pool->free_list;
    pool->free_list = pool->free_list->next;
    if (!pool->free_list) {
        printf("allocate_node: pool->free_list is NULL\n");
        return NULL;  // 内存池已空
    }
    return node;
}

int write_back_num(luca_blockdev_t *bdev, int count, bool inending)
{
    kprintf("写回一批: cnt = %d\n", count);
    if(count <= 0)
        return EOK;
    cache_queue_t *queue = bdev->data_cache_queue;
    cache_dirty_list_t *dirty_list = queue->dirty_list;
    cache_node_t *temp = dirty_list->front;
    uint32_t pb_cnt = bdev->lg_bsize / bdev->bdif->ph_bsize;

    int cnt = dirty_list->size < count ? dirty_list->size : count;


    int r;
    int block_cnt = 0;
    uint64_t start = temp->cache.blk_id;
    uint64_t pba = (start * bdev->lg_bsize + bdev->part_offset) / bdev->bdif->ph_bsize;

    // if(inending)
    //     printf("写回一批: start = %ld, pba = %ld, cnt = %ld\n", start, pba, cnt);

    uint8_t *buf = (uint8_t *)malloc(4096 * cnt);

    // if(inending)
    //     printf("批量写回1\n");
    uint8_t *current = buf;
    // printf("批量写回2\n");
    for(int i = 0; i < cnt; i++)
    {
        // printf("write_back_num: temp->cache.blk_id = %d\n", temp->cache.blk_id);
        memcpy(current, temp->cache.data, 4096);
        current += 4096;
        block_cnt++;

        if(temp->next && (temp->next->cache.blk_id == temp->cache.blk_id + 1) && inending)
        {
           // printf("连续的块号：%d\n", temp->cache.blk_id);
        }
        else
        {/*不连续了把前面连续的部分写入*/
            // if(inending)
            //     printf("写回一批: block_cnt = %d\n", block_cnt);
            r = bdev->bdif->bwrite(bdev, buf, pba, block_cnt*pb_cnt);
            bdev->bdif->bwrite_ctr++;
            if(r != EOK)
                printf("write_back_num: write error\n");

            // if(inending)
            //     printf("写回结束一批: r = %d\n", r);

            block_cnt = 0;
            if(temp->next)
            {
                start = temp->next->cache.blk_id; 
                pba = (start * bdev->lg_bsize + bdev->part_offset) / bdev->bdif->ph_bsize;
                current = buf;
            }
        }

        // 释放当前节点,并将temp指向下一个节点
        cache_node_t *next = temp->next;
        dirty_map.erase(temp->cache.blk_id);

        
        temp = next;
    }


    dirty_list->front = temp;
    dirty_list->size -= cnt;
    // printf("脏链头此时是：%d\n", dirty_list->front->cache.blk_id);

    ext4_free(buf);

    return EOK;
}

int insert_dirty_list(luca_blockdev_t *bdev, cache_node_t *node)
{
    cache_queue_t *queue = bdev->data_cache_queue;
    cache_dirty_list_t *dirty_list = queue->dirty_list;
    // printf("insert_dirty_list: node->cache.blk_id = %d\n", node->cache.blk_id);

    if(!node)
    {
        printf("insert_dirty_list: node is NULL\n");
        return -1;
    }

    auto it = dirty_map.find(node->cache.blk_id);
    if(it != dirty_map.end())
    {
        memcpy(it->second->cache.data, node->cache.data, 4096);
    }
    else
    {
        // cache_node_t *temp = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
        cache_node_t *temp;
        temp = allocate_node(queue);
        if(temp == NULL)
        {
            printf("insert_dirty_list: no free node\n");
            temp = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
        }

        temp->cache.blk_id = node->cache.blk_id;
        memcpy(temp->cache.data, node->cache.data, 4096);
        temp->is_dirty = true;

        // 新节点插入队尾
        temp->next = NULL;
        temp->prev = dirty_list->rear;

        if(dirty_list->rear)
            dirty_list->rear->next = temp;
        else
            dirty_list->front = temp;

        dirty_list->rear = temp;

        // // 查找插入位置
        // cache_node_t *current = dirty_list->front;
        // cache_node_t *prev = NULL;

        // while(current && current->cache.blk_id < node->cache.blk_id)
        // {
        //     prev = current;
        //     current = current->next;
        // }

        // temp->next = current;
        // temp->prev = prev;

        // if(prev)
        //     prev->next = temp;
        // else
        //     dirty_list->front = temp;

        // if(current)
        //     current->prev = temp;
        // else
        //     dirty_list->rear = temp;

        dirty_list->size++;
        dirty_map[node->cache.blk_id] = temp;
    }

    if(dirty_list->size > dirty_list->upper)
        write_back_num(bdev, dirty_list->upper/2, 0);
    
    return EOK;
    // /*按blk顺序排列插入*/
    // if(!dirty_list->front || node->cache.blk_id < dirty_list->front->cache.blk_id)
    // {
    //     cache_node_t *node_insert = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
    //     node_insert->cache.blk_id = node->cache.blk_id;
    //     memcpy(node_insert->cache.data, node->cache.data, 4096);
    //     node_insert->is_dirty = true;

    //     node_insert->next = dirty_list->front;
    //     node_insert->prev = NULL;
    //     if(dirty_list->front)
    //         dirty_list->front->prev = node_insert;

    //     dirty_list->front = node_insert;
    //     if(!dirty_list->rear)
    //         dirty_list->rear = node_insert;

    //     dirty_list->size++;
    // }
    // else
    // {
    //     cache_node_t *temp = dirty_list->front;
    //     while(temp->next && temp->next->cache.blk_id < node->cache.blk_id)
    //         temp = temp->next;
        
    //     if(node->cache.blk_id == temp->cache.blk_id)
    //     {/*如果这个块号本就在脏链里面，直接将其覆盖*/
    //         memcpy(temp->cache.data, node->cache.data, 4096);
    //     }
    //     else
    //     {/*不再脏链里，就再创一个节点插入*/
    //         cache_node_t *node_insert = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
    //         node_insert->cache.blk_id = node->cache.blk_id;
    //         memcpy(node_insert->cache.data, node->cache.data, 4096);
    //         node_insert->is_dirty = true;

    //         node_insert->next = temp->next;
    //         node_insert->prev = temp;
            
    //         if(temp->next)
    //             temp->next->prev = node_insert;

    //         temp->next = node_insert;
    //         if(!node_insert->next)
    //             dirty_list->rear = node_insert;

    //         dirty_list->size++;
    //         // printf("dirty数目：%d\n", dirty_list->size);
    //     }
    // }


}

cache_node* node_to_replace(luca_blockdev_t *bdev)
{
    
    // printf("进入node_to_replace\n");
    cache_queue_t *queue = bdev->data_cache_queue;
    cache_node_t *temp = queue->rear;
    if(!temp)
    {
        printf("node_to_replace: queue is empty\n");
        return nullptr;
    }
    
    queue->rear = temp->prev;
    if(queue->rear)
        queue->rear->next = NULL;
    else
        queue->front = NULL;

    queue->size--;

    // 从哈希表中删除
    cache_map.erase(temp->cache.blk_id);
    

    return temp;
    
}

int cache_insert(luca_blockdev_t *bdev, cache_node *node)
{
    cache_queue_t *queue = bdev->data_cache_queue;
    // printf("进入cache_insert\n");
    //printf("queue->size = %d\n", queue->size);
    cache_node *node_replace;
    if(is_queue_full(queue))
    {
        printf("cache_insert: queue is full\n");
        return -1;
    }

    //如果队列为空，新节点既是头节点又是尾节点
    if(is_queue_empty(queue))
    {
        //printf("进入cache_insert,空队列情况\n");
        queue->front = queue->rear = node;
        node->next = node->prev = NULL;
    }
    else
    {// 否则将新节点放到队列头部
        node->next = queue->front;
        queue->front->prev = node;
        node->prev = NULL;
        queue->front = node;
    }
    queue->size++;

    // 将节点插入哈希表
    cache_map[node->cache.blk_id] = node;

    if(node->is_dirty)
    {
        // cache_node_t *temp = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
        // temp->cache.blk_id = node->cache.blk_id;
        // memcpy(temp->cache.data, node->cache.data, 4096);
        // temp->is_dirty = true;
        // printf("插入脏链\n");
        insert_dirty_list(bdev, node);
    }
    // printf("cache_insert成功\n");

    return EOK;

}


cache_node_t* cache_find(uint64_t lba, luca_blockdev_t *bdev)
{

    auto it = cache_map.find(lba);
    if(it != cache_map.end())
    {
        return it->second;
    }
    return 0;
    // cache_queue *queue = bdev->data_cache_queue;
    // // printf("进入cache_find lba=%d\n", lba);
    // // cache_node *node = (cache_node *)ext4_malloc(sizeof(cache_node));
    // // node = queue->front;
    // cache_node_t *node = queue->front;
    // while (node)
    // {
    //     // printf("进入cache_find2 %d\n", node->cache.blk_id);
    //     if (node->cache.blk_id == lba)
    //     {
    //         // printf("找到了\n");
    //         return node;
    //     }
    //     // printf("进入cache_find3\n");
    //     node = node->next;
    //     // printf("进入cache_find4\n");
    // }
    // // printf("未找到\n");
    // return 0;
}

int cache_one_block(luca_blockdev_t *bdev, uint64_t lba, uint8_t *buffer)
{/*做一个cache块插入*/
    cache_queue *queue = bdev->data_cache_queue;
    if(is_queue_full(queue))
    {/*如果满了，直接替换满掉，然后重新插入*/
        cache_node_t *node_replace = node_to_replace(bdev);
        node_replace->cache.blk_id = lba;
        memcpy(node_replace->cache.data, buffer, 4096);
        node_replace->is_dirty = true;
        cache_insert(bdev, node_replace);
    }
    else
    {/*没满就做一个新的插入*/
        // cache_node_t *node = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
        cache_node_t *node;
        node = allocate_node(queue);
        if(node == NULL)
        {
            printf("cache_one_block: memmory full\n");
            node = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
        }

        node->cache.blk_id = lba;
        memcpy(node->cache.data, buffer, 4096);
        node->is_dirty = true;
        cache_insert(bdev, node);
    }
    return EOK;

}

/*缓存从lba开始的cnt个块，并缓存lba这个块*/
cache_node_t* cache_num_sectors_from_disk(luca_blockdev_t *bdev, uint64_t lba, uint32_t cnt)
{/*既然要从disk里面查了，那肯定是读的时候没有命中*/
    //printf("进入cache_num_sectors %d\n", cnt);
    cache_queue *queue = bdev->data_cache_queue;
    int r;
    uint8_t buf[4096*cnt];
    uint64_t pba = (lba * bdev->lg_bsize + bdev->part_offset) / bdev->bdif->ph_bsize;
    uint32_t pb_cnt = bdev->lg_bsize / bdev->bdif->ph_bsize;

    r = bdev->bdif->bread(bdev, buf, pba, cnt*pb_cnt);
    if(r != EOK)
        printf("cache_num_sectors: read error\n");
    bdev->bdif->bread_ctr++;

    cache_node_t *node2return;
    for(int i = 0; i < cnt; i++)
    {
        if(is_queue_full(queue))
        {
            cache_node_t *node_replace = node_to_replace(bdev);
            node_replace->cache.blk_id = lba + i;
            memcpy(node_replace->cache.data, buf + 4096*i, 4096);
            node_replace->is_dirty = false;
            cache_insert(bdev, node_replace);
            if(i == 0)
                node2return = node_replace;
        }
        else
        {
            // cache_node_t *node = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
            cache_node_t *node;
            node = allocate_node(queue);
            if(node == NULL)
            {
                printf("cache_num_sectors: memmory full\n");
                node = (cache_node_t *)ext4_malloc(sizeof(cache_node_t));
            }

            node->cache.blk_id = lba + i;
            memcpy(node->cache.data, buf + 4096*i, 4096);
            node->is_dirty = false;
            cache_insert(bdev, node);
            if(i == 0)
                node2return = node;
        }
    }    
    return node2return;
}

