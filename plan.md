1. The `INPUT_HANDLER_TASK_STACK_SIZE` is either 4096 or 2048 depending on the board memory (probably 2048 if small RAM or no PSRAM).
2. Inside `BW16::otaUpdate(File& file)`:
   - `uint8_t dataBlock[1029] = {0};`
   - `uint8_t block0[133] = {0};`
   - These arrays allocate 1162 bytes on the stack.
3. If the task stack size is 2048 bytes, allocating 1162 bytes inside `otaUpdate`, plus whatever was allocated in `BW16Menu::optionsMenu` (like `std::vector<Option>`, `std::function`, lambda captures, `loopSD` recursive calls and local variables) will almost certainly cause a **Stack Overflow**, resulting in the ESP32 resetting automatically.
4. To fix this, I should allocate the `dataBlock` dynamically on the heap using `malloc()` or `new`, or change them to static variables (but static is not thread-safe, heap is better).
5. In `src/modules/bw16/BW16.cpp`:
   Instead of:
   ```cpp
   uint8_t block0[133] = {0};
   ...
   uint8_t dataBlock[1029] = {0};
   ```
   Do:
   ```cpp
   uint8_t *block0 = (uint8_t*)calloc(133, 1);
   if(!block0) return false;
   ...
   uint8_t *dataBlock = (uint8_t*)calloc(1029, 1);
   if(!dataBlock) { free(block0); return false; }
   ...
   // before return:
   free(block0);
   free(dataBlock);
   ```
6. Also, inside `while(millis() - startWait < 15000)`, it's updating UI every 100ms. Is that okay? Yes, `progressHandler` is fast.
7. I will refactor `BW16::otaUpdate(File& file)` to use heap allocation for those large buffers.
