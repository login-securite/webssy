"""
Async worker pool with semaphore for concurrency control
"""
import asyncio
from typing import List, Callable, Any, Optional, Awaitable
from asyncio import Semaphore


class WorkerPool:
    def __init__(self, max_workers: int = 20):
        self.semaphore = Semaphore(max_workers)
        self.max_workers = max_workers

    async def map(
        self,
        func: Callable[[Any], Awaitable[Any]],
        items: List[Any],
        progress_callback: Optional[Callable[[Any], None]] = None
    ) -> List[Any]:
        """
        Map async function over items with concurrency control

        Args:
            func: Async function to apply
            items: Items to process
            progress_callback: Optional callback for progress updates

        Returns:
            List of results
        """
        async def bounded_task(item):
            async with self.semaphore:
                result = await func(item)
                if progress_callback:
                    progress_callback(result)
                return result

        tasks = [bounded_task(item) for item in items]
        return await asyncio.gather(*tasks, return_exceptions=False)
