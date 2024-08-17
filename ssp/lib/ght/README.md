# GHT - Generic Hash Table
Simple Hash Table implementation in C
### Features
 *  Dynamic sizing based on load factor, with adjustable max & min thresholds (default: 0.2/0.7).
 *  Thread-Safe.
 *  Automatic memory management (if `ght_t::free` is provided).
 *  Generic Types.

### Hashing Function
* Division.

### Collision Handling
* Changing with Linked-Lists.

### Time Complexity
> For insert / search / delete
* Average-case: O(1)
* Worst-case: O(n)

# Build
> Setup
```
meson setup build/
```
> Compile
```
ninja -C build/
```
> Run
```
./build/example/example
```
# Next
Binary Search Tree / Red-Black Tree
