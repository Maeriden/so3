#include "platform.h"


typedef void ThreadTask(void*);

typedef struct ThreadJob
{
	struct ThreadJob* next;

	ThreadTask* task;
	void*       args;
} ThreadJob;


typedef struct ThreadPool
{
	u32       threads_count;
	thread_t* threads;

	b32 alive;
	critsec_t  queue_critsec;
	condvar_t  queue_condvar;
	u32        queue_len;
	ThreadJob* queue_head;
} ThreadPool;


static
THREAD_CALLBACK_SIGNATURE(thread_pool_callback, param)
{
	ThreadPool* pool = param;
	while(1)
	{
		ThreadJob* job = NULL;

		platform_critsec_enter(&pool->queue_critsec);
		{
			while(pool->alive && !pool->queue_head)
			{
				if(platform_condvar_wait(&pool->queue_condvar, &pool->queue_critsec) != 0)
				{
					PRINT_ERROR("platform_condvar_wait() failed");
					platform_critsec_leave(&pool->queue_critsec);
					THREAD_CALLBACK_RETURN;
				}
			}

			if(!pool->alive)
				break;
			ASSERT(pool->queue_head);

			// Dequeue job
			job = pool->queue_head;
			pool->queue_head = pool->queue_head->next;
			pool->queue_len -= 1;

		}
		platform_critsec_leave(&pool->queue_critsec);

		if(job)
		{
			job->task(job->args);
			memory_free(ThreadJob, job, 1);
		}
	}

	platform_critsec_leave(&pool->queue_critsec);
	THREAD_CALLBACK_RETURN;
}


i32 thread_pool_enqueue_task(ThreadPool* pool, ThreadTask* task, void* task_arg)
{
	if(!(pool->threads_count && pool->threads && task))
		return -1;

	ThreadJob* job = memory_alloc(ThreadJob, 1);
	if(!job)
	{	
		return -1;
	}
	job->task = task;
	job->args = task_arg;
	job->next = NULL;

	platform_critsec_enter(&pool->queue_critsec);
	{
		if(!pool->queue_head)
		{
			pool->queue_head = job;
		}
		else
		{
			ThreadJob* tail = pool->queue_head;
			while(tail->next)
				tail = tail->next;
			tail->next = job;
		}
		pool->queue_len += 1;

		platform_condvar_notify_any(&pool->queue_condvar);
	}
	platform_critsec_leave(&pool->queue_critsec);

	return 0;
}


i32 thread_pool_destroy_impl(ThreadPool* pool, u32 join_count)
{
	platform_critsec_enter(&pool->queue_critsec);
	pool->alive = 0;
	platform_condvar_notify_all(&pool->queue_condvar);
	platform_critsec_leave(&pool->queue_critsec);

	for(u32 i = 0; i < join_count; ++i)
	{
		platform_thread_join(&pool->threads[i]);
	}

	// NOTE: This is not a critical section because we waited for all the threads to terminate
	while(pool->queue_head)
	{
		ThreadJob* job = pool->queue_head;
		pool->queue_head = job->next;
		pool->queue_len -= 1;
		memory_free(ThreadJob, job, 1);
	}

	memory_free(thread_t, pool->threads, pool->threads_count);
	pool->threads       = NULL;
	pool->threads_count = 0;

	platform_condvar_destroy(&pool->queue_condvar);
	platform_critsec_destroy(&pool->queue_critsec);
	return 0;
}
#define thread_pool_destroy(pool) thread_pool_destroy_impl(pool, (pool)->threads_count)


i32 thread_pool_init(ThreadPool* pool, u32 threads_count)
{
	ASSERT(threads_count > 0);
	ASSERT(pool->threads_count == 0);
	ASSERT(pool->threads == NULL);

	if(platform_critsec_init(&pool->queue_critsec) != 0)
	{
		PRINT_ERROR("platform_critsec_init() failed");
		return -1;
	}
	if(platform_condvar_init(&pool->queue_condvar) != 0)
	{
		PRINT_ERROR("platform_condvar_init() failed");
		return -1;
	}

	pool->threads_count = threads_count;
	pool->threads = memory_alloc(thread_t, threads_count);
	if(!pool->threads)
	{
		platform_condvar_destroy(&pool->queue_condvar);
		platform_critsec_destroy(&pool->queue_critsec);
		return -1;
	}

	// NOTE: Set these now so thread_pool_destroy_impl() works correctly if called from the next loop
	pool->alive = 1;
	pool->queue_len = 0;
	pool->queue_head = NULL;

	for(u32 i = 0; i < threads_count; ++i)
	{
		thread_t thread;
		if(platform_thread_init(&thread, thread_pool_callback, pool) != 0)
		{
			PRINT_ERROR("platform_thread_init() failed");
			thread_pool_destroy_impl(pool, i);
			return -1;
		}
		pool->threads[i] = thread;
	}

	return 0;
}
