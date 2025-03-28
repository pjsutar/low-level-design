# Low Level Design Concepts Cheatsheet

## Class Identification Techniques

### Noun Analysis
Identify nouns in the problem statement as potential classes. For example, in "Design a library management system," nouns like "library," "book," "member," and "librarian" become candidate classes.

### CRC Cards
A structured way to organize class responsibilities:
* **Class**: What entity is being modeled
* **Responsibility**: What the class knows and does
* **Collaborator**: Other classes it interacts with
This helps visualize relationships and balance responsibilities.

### Responsibility Driven Design
Focus on what the system needs to do, then assign these responsibilities to appropriate classes:
1. Identify system responsibilities (actions and knowledge)
2. Assign to appropriate classes based on information expert principle
3. Establish how classes communicate (collaboration patterns)

## SOLID Principles

### Single Responsibility Principle
A class should have only one reason to change. This improves maintainability and reduces coupling.

```cpp
// Bad
class UserManager {
    void createUser() { /* ... */ }
    void generateReport() { /* ... */ }  // Unrelated responsibility
};

// Good
class UserManager {
    void createUser() { /* ... */ }
};

class ReportGenerator {
    void generateReport() { /* ... */ }
};
```

### Open/Closed Principle
Software entities should be open for extension but closed for modification. Add new functionality by extending rather than changing existing code.

```cpp
// Bad
class Rectangle {
public:
    virtual double calculateArea() { return width * height; }
    double width;
    double height;
};

// Good
class Shape {
public:
    virtual double calculateArea() = 0;  // Open for extension
};

class Rectangle : public Shape {
public:
    double calculateArea() override { return width * height; }
    double width;
    double height;
};

class Circle : public Shape {
public:
    double calculateArea() override { return 3.14159 * radius * radius; }
    double radius;
};
```

### Liskov Substitution Principle
Subtypes must be substitutable for their base types without altering program correctness. This ensures inheritance hierarchies make semantic sense.

```cpp
class Bird {
public:
    virtual void fly() = 0;
};

// Problem: Not all birds can fly
class Penguin : public Bird {
public:
    void fly() override { throw std::runtime_error("Cannot fly"); }  // Violates LSP
};

// Better design
class Bird {
    // Common bird behaviors
};

class FlyingBird : public Bird {
public:
    virtual void fly() = 0;
};

class Penguin : public Bird {
    // No fly method
};
```

### Interface Segregation Principle
No client should be forced to depend on methods it does not use. Create focused, specific interfaces rather than general-purpose ones.

```cpp
// Bad: Fat interface
class Worker {
public:
    virtual void work() = 0;
    virtual void eat() = 0;
    virtual void sleep() = 0;
};

// Better: Segregated interfaces
class Workable {
public:
    virtual void work() = 0;
};

class Eatable {
public:
    virtual void eat() = 0;
};

class Human : public Workable, public Eatable {
public:
    void work() override { /* ... */ }
    void eat() override { /* ... */ }
};

class Robot : public Workable {
public:
    void work() override { /* ... */ }
    // No need to implement eat()
};
```

### Dependency Inversion Principle
High-level modules should not depend on low-level modules; both should depend on abstractions. This reduces coupling and improves flexibility.

```cpp
// Bad
class LightBulb {
public:
    void turnOn() { /* ... */ }
    void turnOff() { /* ... */ }
};

class Switch {
    LightBulb bulb;
public:
    void operate() {
        // Directly depends on LightBulb implementation
    }
};

// Good
class Switchable {
public:
    virtual void turnOn() = 0;
    virtual void turnOff() = 0;
};

class LightBulb : public Switchable {
public:
    void turnOn() override { /* ... */ }
    void turnOff() override { /* ... */ }
};

class Fan : public Switchable {
public:
    void turnOn() override { /* ... */ }
    void turnOff() override { /* ... */ }
};

class Switch {
    Switchable& device;  // Depends on abstraction
public:
    Switch(Switchable& dev) : device(dev) {}
    void operate() {
        // Works with any Switchable
    }
};
```

## Key Design Patterns

### Creational Patterns

#### Singleton (Thread-safe, C++11)
Ensures a class has only one instance while providing global access. The static initialization in C++11 guarantees thread safety without explicit locks.

```cpp
class Singleton {
private:
    Singleton() = default;
    ~Singleton() = default;
    Singleton(const Singleton&) = delete;
    Singleton& operator=(const Singleton&) = delete;

public:
    static Singleton& getInstance() {
        static Singleton instance;  // Guaranteed to be thread-safe in C++11
        return instance;
    }
};
```

#### Factory Method
Defines an interface for creating objects but lets subclasses decide which classes to instantiate. This decouples object creation from usage.

```cpp
class Product {
public:
    virtual ~Product() = default;
    virtual void operation() = 0;
};

class ConcreteProductA : public Product {
public:
    void operation() override { /* ... */ }
};

class Creator {
public:
    virtual ~Creator() = default;
    virtual std::unique_ptr<Product> createProduct() = 0;
    
    void doSomething() {
        std::unique_ptr<Product> product = createProduct();
        product->operation();
    }
};

class ConcreteCreatorA : public Creator {
public:
    std::unique_ptr<Product> createProduct() override {
        return std::make_unique<ConcreteProductA>();
    }
};
```

### Structural Patterns

#### Adapter
Allows incompatible interfaces to work together by wrapping an object with a new interface. Useful for integrating legacy or third-party code.

```cpp
class Target {
public:
    virtual ~Target() = default;
    virtual void request() = 0;
};

class Adaptee {
public:
    void specificRequest() { /* ... */ }
};

class Adapter : public Target {
private:
    Adaptee adaptee;
    
public:
    void request() override {
        adaptee.specificRequest();
    }
};
```

#### Composite
Composes objects into tree structures to represent part-whole hierarchies, allowing clients to treat individual objects and compositions uniformly.

```cpp
class Component {
public:
    virtual ~Component() = default;
    virtual void operation() = 0;
    virtual void add(Component*) { /* Default no-op */ }
    virtual void remove(Component*) { /* Default no-op */ }
    virtual Component* getChild(int) { return nullptr; }
};

class Leaf : public Component {
public:
    void operation() override { /* ... */ }
};

class Composite : public Component {
private:
    std::vector<Component*> children;
    
public:
    void operation() override {
        for (auto& child : children) {
            child->operation();
        }
    }
    
    void add(Component* component) override {
        children.push_back(component);
    }
    
    void remove(Component* component) override {
        // Remove component from children
    }
    
    Component* getChild(int index) override {
        return children[index];
    }
};
```

### Behavioral Patterns

#### Observer
Defines a one-to-many dependency between objects, so that when one object changes state, all its dependents are notified automatically. Useful for event handling systems.

```cpp
class Observer {
public:
    virtual ~Observer() = default;
    virtual void update(const std::string& message) = 0;
};

class Subject {
private:
    std::vector<Observer*> observers;
    
public:
    void attach(Observer* observer) {
        observers.push_back(observer);
    }
    
    void detach(Observer* observer) {
        // Remove observer from vector
    }
    
    void notify(const std::string& message) {
        for (auto& observer : observers) {
            observer->update(message);
        }
    }
};

class ConcreteObserver : public Observer {
public:
    void update(const std::string& message) override {
        // Handle update
    }
};
```

#### Strategy
Defines a family of algorithms, encapsulates each one, and makes them interchangeable. This allows the algorithm to vary independently from clients that use it.

```cpp
class Strategy {
public:
    virtual ~Strategy() = default;
    virtual void execute() = 0;
};

class ConcreteStrategyA : public Strategy {
public:
    void execute() override { /* ... */ }
};

class ConcreteStrategyB : public Strategy {
public:
    void execute() override { /* ... */ }
};

class Context {
private:
    std::unique_ptr<Strategy> strategy;
    
public:
    void setStrategy(std::unique_ptr<Strategy> s) {
        strategy = std::move(s);
    }
    
    void executeStrategy() {
        if (strategy) {
            strategy->execute();
        }
    }
};
```

## Concurrency Patterns

### Thread Pool
Manages a pool of worker threads to execute tasks asynchronously. Reduces overhead of thread creation and improves resource utilization.

```cpp
class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
    
public:
    ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { 
                            return stop || !tasks.empty(); 
                        });
                        
                        if (stop && tasks.empty()) {
                            return;
                        }
                        
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }
    
    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }
    
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread &worker : workers) {
            worker.join();
        }
    }
};
```

## Common System Components

### LRU Cache
Implements a fixed-size cache that discards the least recently used items first. Combines a hash map for O(1) lookups with a linked list for tracking usage order.

```cpp
template<typename K, typename V>
class LRUCache {
private:
    int capacity;
    std::list<std::pair<K, V>> items;
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> cache;
    
public:
    LRUCache(int size) : capacity(size) {}
    
    V get(K key) {
        auto it = cache.find(key);
        if (it == cache.end()) {
            throw std::runtime_error("Key not found");
        }
        
        // Move to front (most recently used)
        items.splice(items.begin(), items, it->second);
        return it->second->second;
    }
    
    void put(K key, V value) {
        auto it = cache.find(key);
        
        // Remove existing item if present
        if (it != cache.end()) {
            items.erase(it->second);
            cache.erase(it);
        }
        
        // Add new item at front
        items.push_front(std::make_pair(key, value));
        cache[key] = items.begin();
        
        // Remove least recently used if over capacity
        if (cache.size() > capacity) {
            auto last = items.end();
            --last;
            cache.erase(last->first);
            items.pop_back();
        }
    }
};
```

### Rate Limiter (Token Bucket)
Controls the rate of operations by using a token bucket algorithm. Useful for API throttling, traffic shaping, and protecting services from overload.

```cpp
class TokenBucket {
private:
    std::mutex mutex;
    double tokens;
    double capacity;
    double rate;  // tokens per second
    std::chrono::time_point<std::chrono::steady_clock> lastRefill;
    
    void refill() {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastRefill).count() / 1000.0;
        
        double newTokens = duration * rate;
        if (newTokens > 0) {
            tokens = std::min(capacity, tokens + newTokens);
            lastRefill = now;
        }
    }
    
public:
    TokenBucket(double capacity, double rate)
        : tokens(capacity), capacity(capacity), rate(rate),
          lastRefill(std::chrono::steady_clock::now()) {}
    
    bool consume(double count = 1.0) {
        std::lock_guard<std::mutex> lock(mutex);
        refill();
        
        if (tokens >= count) {
            tokens -= count;
            return true;
        }
        
        return false;
    }
};
```

## Time & Space Complexity Review

### Common Operations

| Data Structure       | Access    | Search    | Insertion | Deletion  | Notes |
|----------------------|-----------|-----------|-----------|-----------|-------|
| std::vector          | O(1)      | O(n)      | O(1)/O(n) | O(n)      | O(1) amortized insertion at end; O(n) for middle insertions |
| std::list            | O(n)      | O(n)      | O(1)      | O(1)      | O(1) insertion/deletion with iterator position |
| std::map             | O(log n)  | O(log n)  | O(log n)  | O(log n)  | Red-black tree implementation |
| std::unordered_map   | O(1)      | O(1)      | O(1)      | O(1)      | O(n) worst case with hash collisions |
| std::priority_queue  | O(1)      | O(n)      | O(log n)  | O(log n)  | Binary heap implementation; O(1) for top element |

### Memory Considerations
- **Contiguous containers**: Better cache locality, faster iteration, but more expensive resizing (std::vector, std::array)
- **Node-based containers**: More stable iterators, better for frequent insertion/deletion (std::list, std::map)
- **Small object optimization**: Many STL implementations optimize storage for small objects to avoid heap allocation
- **std::vector reallocation**: Typically doubles capacity on reallocation, leading to O(1) amortized insertion

# Essential Low Level Designs for Interviews

This comprehensive guide covers the design and implementation of five key low-level systems commonly asked about in technical interviews:
The File System design is fully implemented. Only the key components in other designs are implemented.

1. [File System](#1-file-system)
2. [Rate Limiter](#2-rate-limiter)
3. [Thread-Safe Cache with Expiration](#3-thread-safe-cache-with-expiration)
4. [Logging Framework](#4-logging-framework)
5. [Object Pool](#5-object-pool)

Each section includes:
- Core requirements
- Main components and interfaces
- Key implementations
- Design patterns used
- Thread safety considerations
- Extension points
- Time and space complexity analysis

## 1. File System

### Core Requirements

- Organize files in a hierarchical structure (directories and files)
- Support basic operations: create, read, write, delete, move, and list
- Implement proper access control
- Handle file metadata (creation time, modification time, size, etc.)
- Ensure thread safety for concurrent operations

### Design: Composite Pattern Implementation

The file system design uses the Composite pattern to represent the hierarchical structure of files and directories:

```cpp
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <sstream>
#include <algorithm>

// Forward declarations
class User;
class FileSystemEntry;
class File;
class Directory;

// Enums and helper classes
enum class FilePermission { READ, WRITE, EXECUTE };
enum class Operation { READ, WRITE, EXECUTE, DELETE, RENAME };

struct TimeInfo {
    std::chrono::system_clock::time_point timestamp;
    
    TimeInfo() : timestamp(std::chrono::system_clock::now()) {}
    
    std::string toString() const {
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        std::string timeStr = std::ctime(&time_t);
        // Remove newline character
        if (!timeStr.empty() && timeStr[timeStr.length() - 1] == '\n') {
            timeStr.erase(timeStr.length() - 1);
        }
        return timeStr;
    }
};

class FilePermissions {
private:
    bool ownerRead = true;
    bool ownerWrite = true;
    bool ownerExecute = false;
    bool groupRead = true;
    bool groupWrite = false;
    bool groupExecute = false;
    bool othersRead = true;
    bool othersWrite = false;
    bool othersExecute = false;
    std::string owner;
    std::string group;

public:
    FilePermissions(const std::string& owner = "root", const std::string& group = "root")
        : owner(owner), group(group) {}
    
    bool checkPermission(Operation op, const User& user) const;
    
    // Setters for permissions
    void setOwnerPermission(FilePermission perm, bool value);
    void setGroupPermission(FilePermission perm, bool value);
    void setOthersPermission(FilePermission perm, bool value);
    
    std::string toString() const;
};

class User {
private:
    std::string username;
    std::vector<std::string> groups;

public:
    User(const std::string& name = "") : username(name) {
        if (!name.empty()) {
            groups.push_back(name); // Default group is same as username
        }
    }
    
    std::string getUsername() const { return username; }
    const std::vector<std::string>& getGroups() const { return groups; }
    void addGroup(const std::string& group) { groups.push_back(group); }
};

// Base class for the Composite Pattern
class FileSystemEntry {
private:
    std::string name;
    std::string path;
    FilePermissions permissions;
    TimeInfo creationTime;
    TimeInfo modificationTime;
    FileSystemEntry* parent;

public:
    FileSystemEntry(const std::string& name, FileSystemEntry* parent = nullptr)
        : name(name), parent(parent) {
        updatePath();
    }
    
    virtual ~FileSystemEntry() = default;
    
    // Pure virtual methods - must be implemented by derived classes
    virtual bool isDirectory() const = 0;
    virtual size_t getSize() const = 0;
    
    // Common functionality
    std::string getName() const { return name; }
    std::string getPath() const { return path; }
    FilePermissions getPermissions() const { return permissions; }
    TimeInfo getCreationTime() const { return creationTime; }
    TimeInfo getModificationTime() const { return modificationTime; }
    FileSystemEntry* getParent() const { return parent; }
    
    void setName(const std::string& newName) {
        name = newName;
        updatePath();
        updateModificationTime();
    }
    
    void setParent(FileSystemEntry* newParent) {
        parent = newParent;
        updatePath();
    }
    
    void updateModificationTime() {
        modificationTime = TimeInfo();
    }
    
    bool checkPermission(Operation op, const User& user) const {
        return permissions.checkPermission(op, user);
    }
    
private:
    void updatePath() {
        if (parent == nullptr) {
            path = "/" + name;
        } else {
            path = parent->getPath();
            if (path != "/") {
                path += "/";
            }
            path += name;
        }
    }
};

// Leaf class in the Composite Pattern
class File : public FileSystemEntry {
private:
    std::vector<uint8_t> content;
    mutable std::mutex fileMutex;

public:
    File(const std::string& name, FileSystemEntry* parent)
        : FileSystemEntry(name, parent) {}
    
    // Implementation of pure virtual methods
    bool isDirectory() const override { return false; }
    size_t getSize() const override { 
        std::lock_guard<std::mutex> lock(fileMutex);
        return content.size(); 
    }
    
    // File-specific operations
    std::vector<uint8_t> read() const {
        std::lock_guard<std::mutex> lock(fileMutex);
        return content;
    }
    
    void write(const std::vector<uint8_t>& data, size_t position = 0) {
        std::lock_guard<std::mutex> lock(fileMutex);
        
        if (position > content.size()) {
            position = content.size();
        }
        
        if (position + data.size() > content.size()) {
            content.resize(position + data.size());
        }
        
        std::copy(data.begin(), data.end(), content.begin() + position);
        updateModificationTime();
    }
    
    void append(const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(fileMutex);
        content.insert(content.end(), data.begin(), data.end());
        updateModificationTime();
    }
    
    void truncate(size_t size) {
        std::lock_guard<std::mutex> lock(fileMutex);
        content.resize(size);
        updateModificationTime();
    }
};

// Composite class in the Composite Pattern
class Directory : public FileSystemEntry {
private:
    std::unordered_map<std::string, std::shared_ptr<FileSystemEntry>> entries;
    mutable std::mutex directoryMutex;

public:
    Directory(const std::string& name, FileSystemEntry* parent)
        : FileSystemEntry(name, parent) {}
    
    // Implementation of pure virtual methods
    bool isDirectory() const override { return true; }
    
    size_t getSize() const override {
        std::lock_guard<std::mutex> lock(directoryMutex);
        size_t totalSize = 0;
        for (const auto& entry : entries) {
            totalSize += entry.second->getSize();
        }
        return totalSize;
    }
    
    // Directory-specific operations
    std::vector<std::string> list() const {
        std::lock_guard<std::mutex> lock(directoryMutex);
        std::vector<std::string> result;
        result.reserve(entries.size());
        
        for (const auto& entry : entries) {
            result.push_back(entry.first + (entry.second->isDirectory() ? "/" : ""));
        }
        
        std::sort(result.begin(), result.end());
        return result;
    }
    
    bool addEntry(const std::shared_ptr<FileSystemEntry>& entry) {
        std::lock_guard<std::mutex> lock(directoryMutex);
        
        std::string entryName = entry->getName();
        if (entries.find(entryName) != entries.end()) {
            return false;  // Entry already exists
        }
        
        entries[entryName] = entry;
        entry->setParent(this);
        updateModificationTime();
        return true;
    }
    
    bool removeEntry(const std::string& name) {
        std::lock_guard<std::mutex> lock(directoryMutex);
        
        auto it = entries.find(name);
        if (it == entries.end()) {
            return false;  // Entry not found
        }
        
        entries.erase(it);
        updateModificationTime();
        return true;
    }
    
    std::shared_ptr<FileSystemEntry> getEntry(const std::string& name) const {
        std::lock_guard<std::mutex> lock(directoryMutex);
        
        auto it = entries.find(name);
        if (it == entries.end()) {
            return nullptr;  // Entry not found
        }
        
        return it->second;
    }
    
    // Factory methods
    std::shared_ptr<File> createFile(const std::string& name) {
        std::lock_guard<std::mutex> lock(directoryMutex);
        
        if (entries.find(name) != entries.end()) {
            return nullptr;  // File already exists
        }
        
        auto file = std::make_shared<File>(name, this);
        entries[name] = file;
        updateModificationTime();
        return file;
    }
    
    std::shared_ptr<Directory> createDirectory(const std::string& name) {
        std::lock_guard<std::mutex> lock(directoryMutex);
        
        if (entries.find(name) != entries.end()) {
            return nullptr;  // Directory already exists
        }
        
        auto directory = std::make_shared<Directory>(name, this);
        entries[name] = directory;
        updateModificationTime();
        return directory;
    }
};

// FileSystem class - manages the entire file system
class FileSystem {
private:
    std::shared_ptr<Directory> root;
    std::shared_ptr<Directory> currentWorkingDirectory;
    mutable std::recursive_mutex fsMutex;
    std::unordered_map<std::string, User> users;
    User currentUser;

public:
    FileSystem() : currentUser("root") {
        // Create root directory
        root = std::make_shared<Directory>("", nullptr);  // Root has an empty name
        currentWorkingDirectory = root;
        
        // Add default user
        users["root"] = currentUser;
    }
    
    // Path resolution - a key function for navigating the file system
    std::shared_ptr<FileSystemEntry> resolvePath(const std::string& path) const {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        // Handle special case for root directory
        if (path == "/") {
            return root;
        }
        
        // Determine starting directory for relative or absolute paths
        std::shared_ptr<Directory> startDir;
        std::string pathToResolve;
        
        if (path.empty() || path[0] != '/') {
            // Relative path
            startDir = currentWorkingDirectory;
            pathToResolve = path;
        } else {
            // Absolute path
            startDir = root;
            pathToResolve = path.substr(1);  // Remove leading '/'
        }
        
        if (pathToResolve.empty()) {
            return startDir;
        }
        
        // Split path into components
        std::vector<std::string> components;
        std::stringstream ss(pathToResolve);
        std::string component;
        
        while (std::getline(ss, component, '/')) {
            if (!component.empty()) {
                components.push_back(component);
            }
        }
        
        // Navigate through components
        std::shared_ptr<FileSystemEntry> current = startDir;
        
        for (const auto& comp : components) {
            if (comp == ".") {
                continue;  // Current directory
            } else if (comp == "..") {
                // Parent directory
                if (current != root) {
                    current = std::shared_ptr<FileSystemEntry>(current->getParent() == nullptr ? 
                                                             root : 
                                                             dynamic_cast<FileSystemEntry*>(current->getParent())->shared_from_this());
                }
            } else {
                // Regular directory or file
                if (!current->isDirectory()) {
                    return nullptr;  // Cannot navigate into a file
                }
                
                auto dir = std::dynamic_pointer_cast<Directory>(current);
                current = dir->getEntry(comp);
                
                if (!current) {
                    return nullptr;  // Path component not found
                }
            }
        }
        
        return current;
    }
    
    // Navigation
    bool changeDirectory(const std::string& path) {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        auto entry = resolvePath(path);
        if (!entry || !entry->isDirectory()) {
            return false;
        }
        
        if (!entry->checkPermission(Operation::EXECUTE, currentUser)) {
            return false;
        }
        
        currentWorkingDirectory = std::dynamic_pointer_cast<Directory>(entry);
        return true;
    }
    
    std::string getCurrentPath() const {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        return currentWorkingDirectory->getPath();
    }
    
    // File operations
    bool createFile(const std::string& path) {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        // Extract directory path and filename
        size_t lastSlash = path.find_last_of('/');
        std::string directoryPath, fileName;
        
        if (lastSlash == std::string::npos) {
            // No slash, create in current directory
            directoryPath = getCurrentPath();
            fileName = path;
        } else {
            directoryPath = path.substr(0, lastSlash);
            fileName = path.substr(lastSlash + 1);
        }
        
        if (directoryPath.empty()) {
            directoryPath = "/";
        }
        
        auto dirEntry = resolvePath(directoryPath);
        if (!dirEntry || !dirEntry->isDirectory()) {
            return false;
        }
        
        auto dir = std::dynamic_pointer_cast<Directory>(dirEntry);
        if (!dir->checkPermission(Operation::WRITE, currentUser)) {
            return false;
        }
        
        return dir->createFile(fileName) != nullptr;
    }
    
    std::vector<uint8_t> readFile(const std::string& path) {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        auto entry = resolvePath(path);
        if (!entry || entry->isDirectory()) {
            return {};  // Return empty vector for errors
        }
        
        if (!entry->checkPermission(Operation::READ, currentUser)) {
            return {};
        }
        
        auto file = std::dynamic_pointer_cast<File>(entry);
        return file->read();
    }
    
    bool writeFile(const std::string& path, const std::vector<uint8_t>& data) {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        auto entry = resolvePath(path);
        if (!entry) {
            // File doesn't exist, try to create it
            if (!createFile(path)) {
                return false;
            }
            entry = resolvePath(path);
        }
        
        if (entry->isDirectory()) {
            return false;
        }
        
        if (!entry->checkPermission(Operation::WRITE, currentUser)) {
            return false;
        }
        
        auto file = std::dynamic_pointer_cast<File>(entry);
        file->write(data);
        return true;
    }
    
    // Directory operations
    bool createDirectory(const std::string& path) {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        // Handle the special case of creating root
        if (path == "/") {
            return false;  // Root already exists
        }
        
        // Extract parent directory path and new directory name
        size_t lastSlash = path.find_last_of('/');
        std::string parentPath, dirName;
        
        if (lastSlash == std::string::npos) {
            // No slash, create in current directory
            parentPath = getCurrentPath();
            dirName = path;
        } else {
            parentPath = path.substr(0, lastSlash);
            dirName = path.substr(lastSlash + 1);
            
            if (parentPath.empty()) {
                parentPath = "/";
            }
        }
        
        auto parentEntry = resolvePath(parentPath);
        if (!parentEntry || !parentEntry->isDirectory()) {
            return false;
        }
        
        auto parentDir = std::dynamic_pointer_cast<Directory>(parentEntry);
        if (!parentDir->checkPermission(Operation::WRITE, currentUser)) {
            return false;
        }
        
        return parentDir->createDirectory(dirName) != nullptr;
    }
    
    std::vector<std::string> listDirectory(const std::string& path = "") {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        std::string dirPath = path.empty() ? getCurrentPath() : path;
        auto entry = resolvePath(dirPath);
        
        if (!entry || !entry->isDirectory()) {
            return {};
        }
        
        if (!entry->checkPermission(Operation::READ, currentUser)) {
            return {};
        }
        
        auto dir = std::dynamic_pointer_cast<Directory>(entry);
        return dir->list();
    }
    
    bool deleteEntry(const std::string& path) {
        std::lock_guard<std::recursive_mutex> lock(fsMutex);
        
        if (path == "/") {
            return false;  // Cannot delete root
        }
        
        // Extract parent path and entry name
        size_t lastSlash = path.find_last_of('/');
        if (lastSlash == std::string::npos) {
            // No slash, delete in current directory
            std::string entryName = path;
            return currentWorkingDirectory->removeEntry(entryName);
        }
        
        std::string parentPath = path.substr(0, lastSlash);
        std::string entryName = path.substr(lastSlash + 1);
        
        if (parentPath.empty()) {
            parentPath = "/";
        }
        
        auto parentEntry = resolvePath(parentPath);
        if (!parentEntry || !parentEntry->isDirectory()) {
            return false;
        }
        
        auto parentDir = std::dynamic_pointer_cast<Directory>(parentEntry);
        if (!parentDir->checkPermission(Operation::WRITE, currentUser)) {
            return false;
        }
        
        return parentDir->removeEntry(entryName);
    }
};

// Implementations of some methods

bool FilePermissions::checkPermission(Operation op, const User& user) const {
    // Root has all permissions
    if (user.getUsername() == "root") {
        return true;
    }
    
    // Check if user is the owner
    if (user.getUsername() == owner) {
        switch (op) {
            case Operation::READ: return ownerRead;
            case Operation::WRITE: return ownerWrite;
            case Operation::EXECUTE: return ownerExecute;
            case Operation::DELETE: return ownerWrite;
            case Operation::RENAME: return ownerWrite;
        }
    }
    
    // Check if user is in the file's group
    const auto& userGroups = user.getGroups();
    if (std::find(userGroups.begin(), userGroups.end(), group) != userGroups.end()) {
        switch (op) {
            case Operation::READ: return groupRead;
            case Operation::WRITE: return groupWrite;
            case Operation::EXECUTE: return groupExecute;
            case Operation::DELETE: return groupWrite;
            case Operation::RENAME: return groupWrite;
        }
    }
    
    // User is neither owner nor in the group
    switch (op) {
        case Operation::READ: return othersRead;
        case Operation::WRITE: return othersWrite;
        case Operation::EXECUTE: return othersExecute;
        case Operation::DELETE: return othersWrite;
        case Operation::RENAME: return othersWrite;
    }
    
    return false;
}

// Example of using this file system
int main() {
    FileSystem fs;
    
    // Create some directories and files
    fs.createDirectory("/home");
    fs.createDirectory("/home/user");
    fs.changeDirectory("/home/user");
    
    // Create and write to a file
    std::string content = "Hello, File System!";
    std::vector<uint8_t> data(content.begin(), content.end());
    fs.createFile("example.txt");
    fs.writeFile("example.txt", data);
    
    // Read file content
    std::vector<uint8_t> readData = fs.readFile("example.txt");
    std::string readContent(readData.begin(), readData.end());
    std::cout << "File content: " << readContent << std::endl;
    
    // List directory contents
    std::cout << "Directory contents:" << std::endl;
    for (const auto& entry : fs.listDirectory()) {
        std::cout << "- " << entry << std::endl;
    }
    
    return 0;
}
```

### Composite Pattern Explained

The Composite pattern enables:

1. **Uniform Treatment**: Both files and directories are treated as `FileSystemEntry` objects
2. **Recursive Operations**: Methods like `getSize()` automatically work recursively through the hierarchy
3. **Tree Traversal**: Path resolution and navigation through the directory structure is simplified
4. **Clean Interface**: Clients work with a unified interface regardless of whether they're dealing with files or directories

### Thread Safety Approach

- Each file has its own mutex for operations specific to that file
- Each directory has its own mutex for directory-specific operations
- The file system has a recursive mutex for operations that span multiple entries
- Locks are acquired in a consistent order to prevent deadlocks

### Time and Space Complexity

- **Path Resolution**: O(m) where m is the path depth
- **File Operations**: O(n) for read/write where n is the file size
- **Directory Listing**: O(n) where n is the number of entries in the directory
- **Space Complexity**: O(n) for files where n is the content size, O(n) for directories where n is the number of entries

### Extension Points

1. **Storage Backend**: Abstract the storage mechanism to support different media types
2. **Journaling**: Add a journal for crash recovery
3. **Quota Management**: Add limits for storage usage by user or directory
4. **Extended Attributes**: Support custom metadata beyond the standard attributes
5. **Caching**: Add a cache layer for frequently accessed files and directories

## 2. Rate Limiter

### Core Requirements

- Limit the number of requests a client can make in a given time window
- Support different rate limiting algorithms (Token Bucket, Leaky Bucket, Fixed Window, Sliding Window)
- Allow for distributed rate limiting
- Provide thread safety for concurrent access
- Support custom configurations per client/API

### Design: Strategy Pattern Implementation

The rate limiter design uses the Strategy pattern to allow different rate limiting algorithms:

```cpp
// Interface for rate limiting strategies
class RateLimitStrategy {
public:
    virtual ~RateLimitStrategy() = default;
    virtual bool allowRequest(const std::string& clientId) = 0;
    virtual void reset(const std::string& clientId) = 0;
};

// Token Bucket implementation
class TokenBucketStrategy : public RateLimitStrategy {
private:
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point lastRefillTime;
    };
    
    std::unordered_map<std::string, Bucket> buckets;
    std::mutex bucketsMutex;
    double refillRate;     // tokens per second
    double maxBucketSize;  // maximum tokens a bucket can hold
    
    void refillBucket(Bucket& bucket) {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - bucket.lastRefillTime).count() / 1000.0;
        
        double newTokens = duration * refillRate;
        if (newTokens > 0) {
            bucket.tokens = std::min(maxBucketSize, bucket.tokens + newTokens);
            bucket.lastRefillTime = now;
        }
    }
    
public:
    TokenBucketStrategy(double rate, double bucketSize)
        : refillRate(rate), maxBucketSize(bucketSize) {}
    
    bool allowRequest(const std::string& clientId) override {
        std::lock_guard<std::mutex> lock(bucketsMutex);
        
        auto& bucket = buckets[clientId];
        if (bucket.lastRefillTime == std::chrono::steady_clock::time_point()) {
            // Initialize new bucket
            bucket.tokens = maxBucketSize;
            bucket.lastRefillTime = std::chrono::steady_clock::now();
        } else {
            refillBucket(bucket);
        }
        
        if (bucket.tokens >= 1.0) {
            bucket.tokens -= 1.0;
            return true;
        }
        
        return false;
    }
    
    void reset(const std::string& clientId) override {
        std::lock_guard<std::mutex> lock(bucketsMutex);
        buckets.erase(clientId);
    }
};

// Sliding Window implementation
class SlidingWindowStrategy : public RateLimitStrategy {
private:
    struct Window {
        std::deque<std::chrono::steady_clock::time_point> requests;
    };
    
    std::unordered_map<std::string, Window> windows;
    std::mutex windowsMutex;
    int maxRequests;
    std::chrono::milliseconds windowSize;
    
    void cleanupWindow(Window& window) {
        auto now = std::chrono::steady_clock::now();
        auto cutoff = now - windowSize;
        
        while (!window.requests.empty() && window.requests.front() < cutoff) {
            window.requests.pop_front();
        }
    }
    
public:
    SlidingWindowStrategy(int requests, std::chrono::milliseconds window)
        : maxRequests(requests), windowSize(window) {}
    
    bool allowRequest(const std::string& clientId) override {
        std::lock_guard<std::mutex> lock(windowsMutex);
        
        auto& window = windows[clientId];
        cleanupWindow(window);
        
        if (window.requests.size() < maxRequests) {
            window.requests.push_back(std::chrono::steady_clock::now());
            return true;
        }
        
        return false;
    }
    
    void reset(const std::string& clientId) override {
        std::lock_guard<std::mutex> lock(windowsMutex);
        windows.erase(clientId);
    }
};
```

### The Rate Limiter Class

```cpp
class RateLimiter {
private:
    std::unordered_map<std::string, std::shared_ptr<RateLimitStrategy>> strategies;
    std::shared_ptr<RateLimitStrategy> defaultStrategy;
    std::mutex strategiesMutex;

public:
    RateLimiter(std::shared_ptr<RateLimitStrategy> defaultStrat) 
        : defaultStrategy(defaultStrat) {}
    
    bool allowRequest(const std::string& clientId, const std::string& resourceId = "") {
        std::lock_guard<std::mutex> lock(strategiesMutex);
        
        std::string key = resourceId.empty() ? clientId : clientId + ":" + resourceId;
        
        auto it = strategies.find(key);
        if (it != strategies.end()) {
            return it->second->allowRequest(clientId);
        }
        
        return defaultStrategy->allowRequest(clientId);
    }
    
    void setStrategy(const std::string& clientId, const std::string& resourceId,
                    std::shared_ptr<RateLimitStrategy> strategy) {
        std::lock_guard<std::mutex> lock(strategiesMutex);
        strategies[clientId + ":" + resourceId] = strategy;
    }
    
    void removeStrategy(const std::string& clientId, const std::string& resourceId) {
        std::lock_guard<std::mutex> lock(strategiesMutex);
        strategies.erase(clientId + ":" + resourceId);
    }
    
    void reset(const std::string& clientId) {
        std::lock_guard<std::mutex> lock(strategiesMutex);
        
        for (auto& pair : strategies) {
            if (pair.first.find(clientId) == 0) {
                pair.second->reset(clientId);
            }
        }
        
        defaultStrategy->reset(clientId);
    }
};
```

### Example Usage

```cpp
// Create a rate limiter with token bucket as default strategy
auto tokenBucket = std::make_shared<TokenBucketStrategy>(10, 50);  // 10 tokens/sec, bucket size 50
RateLimiter limiter(tokenBucket);

// Set a more restrictive strategy for a specific API
auto slidingWindow = std::make_shared<SlidingWindowStrategy>(5, std::chrono::seconds(1));  // 5 req/sec
limiter.setStrategy("user123", "sensitive-api", slidingWindow);

// Check if a request is allowed
if (limiter.allowRequest("user123", "regular-api")) {
    // Process request
} else {
    // Return 429 Too Many Requests
}
```

### Strategy Pattern Explained

The Strategy pattern enables:

1. **Algorithm Encapsulation**: Different rate limiting algorithms are encapsulated in separate classes
2. **Runtime Flexibility**: Strategies can be swapped at runtime without changing client code
3. **Extensibility**: New strategies can be added without modifying existing code
4. **Configurability**: Different strategies can be used for different clients or resources

### Thread Safety Approach

- Each strategy implementation uses its own mutex to protect its data structures
- The rate limiter uses a mutex to protect the strategy map
- Thread safety is contained within each class, avoiding the need for external synchronization

### Time and Space Complexity

- **Token Bucket**: 
  - Time: O(1) for allowRequest
  - Space: O(n) where n is the number of clients
  
- **Sliding Window**:
  - Time: O(m) for allowRequest where m is the number of requests in the window
  - Space: O(n*m) where n is the number of clients and m is the maximum requests per window

### Extension Points

1. **Distributed Rate Limiting**: Integrate with Redis or other distributed storage
2. **Custom Response Handling**: Add support for retry-after headers and custom backoff strategies
3. **Monitoring and Metrics**: Track rate limit hits for analytics
4. **Rule-Based Configuration**: Define rate limits based on user roles or request attributes
5. **Adaptive Rate Limiting**: Dynamically adjust limits based on system load

## 3. Thread-Safe Cache with Expiration

### Core Requirements

- Store key-value pairs with optional time-based expiration
- Support get, put, and remove operations
- Implement LRU (Least Recently Used) eviction policy
- Ensure thread safety for concurrent access
- Support capacity limits

### Design: Decorator Pattern Implementation

The cache design uses the Decorator pattern to add expiration functionality to a base cache:

```cpp
// Base cache interface
template <typename K, typename V>
class Cache {
public:
    virtual ~Cache() = default;
    virtual std::optional<V> get(const K& key) = 0;
    virtual void put(const K& key, const V& value) = 0;
    virtual bool remove(const K& key) = 0;
    virtual size_t size() const = 0;
    virtual void clear() = 0;
};

// LRU Cache implementation
template <typename K, typename V>
class LRUCache : public Cache<K, V> {
private:
    struct CacheNode {
        K key;
        V value;
        
        CacheNode(const K& k, const V& v) : key(k), value(v) {}
    };
    
    std::list<CacheNode> items;
    std::unordered_map<K, typename std::list<CacheNode>::iterator> itemMap;
    size_t maxSize;
    mutable std::mutex cacheMutex;
    
public:
    LRUCache(size_t capacity) : maxSize(capacity) {}
    
    std::optional<V> get(const K& key) override {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        auto it = itemMap.find(key);
        if (it == itemMap.end()) {
            return std::nullopt;
        }
        
        // Move to front (most recently used)
        items.splice(items.begin(), items, it->second);
        return it->second->value;
    }
    
    void put(const K& key, const V& value) override {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        auto it = itemMap.find(key);
        if (it != itemMap.end()) {
            // Update existing item
            it->second->value = value;
            items.splice(items.begin(), items, it->second);
        } else {
            // Add new item
            items.push_front(CacheNode(key, value));
            itemMap[key] = items.begin();
            
            // Evict if over capacity
            if (itemMap.size() > maxSize) {
                auto last = items.end();
                --last;
                itemMap.erase(last->key);
                items.pop_back();
            }
        }
    }
    
    bool remove(const K& key) override {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        auto it = itemMap.find(key);
        if (it == itemMap.end()) {
            return false;
        }
        
        items.erase(it->second);
        itemMap.erase(it);
        return true;
    }
    
    size_t size() const override {
        std::lock_guard<std::mutex> lock(cacheMutex);
        return itemMap.size();
    }
    
    void clear() override {
        std::lock_guard<std::mutex> lock(cacheMutex);
        items.clear();
        itemMap.clear();
    }
};

// Decorator that adds expiration to any cache
template <typename K, typename V>
class ExpiringCache : public Cache<K, V> {
private:
    struct ExpiryInfo {
        std::chrono::steady_clock::time_point expiryTime;
        
        ExpiryInfo(std::chrono::milliseconds ttl = std::chrono::milliseconds::zero())
            : expiryTime(ttl == std::chrono::milliseconds::zero() ? 
                      std::chrono::steady_clock::time_point::max() :
                      std::chrono::steady_clock::now() + ttl) {}
        
        bool isExpired() const {
            return std::chrono::steady_clock::now() >= expiryTime;
        }
    };
    
    std::shared_ptr<Cache<K, V>> wrappedCache;
    std::unordered_map<K, ExpiryInfo> expiryMap;
    std::chrono::milliseconds defaultTTL;
    mutable std::mutex expiryMutex;
    
    void removeExpired() {
        for (auto it = expiryMap.begin(); it != expiryMap.end(); ) {
            if (it->second.isExpired()) {
                wrappedCache->remove(it->first);
                it = expiryMap.erase(it);
            } else {
                ++it;
            }
        }
    }
    
public:
    ExpiringCache(std::shared_ptr<Cache<K, V>> cache, 
                  std::chrono::milliseconds defaultExpiry = std::chrono::milliseconds::zero())
        : wrappedCache(cache), defaultTTL(defaultExpiry) {}
    
    std::optional<V> get(const K& key) override {
        std::lock_guard<std::mutex> lock(expiryMutex);
        
        auto it = expiryMap.find(key);
        if (it != expiryMap.end() && it->second.isExpired()) {
            wrappedCache->remove(key);
            expiryMap.erase(it);
            return std::nullopt;
        }
        
        return wrappedCache->get(key);
    }
    
    void put(const K& key, const V& value, std::chrono::milliseconds ttl = std::chrono::milliseconds::zero()) {
        std::lock_guard<std::mutex> lock(expiryMutex);
        
        wrappedCache->put(key, value);
        
        std::chrono::milliseconds actualTTL = (ttl == std::chrono::milliseconds::zero()) ? defaultTTL : ttl;
        expiryMap[key] = ExpiryInfo(actualTTL);
        
        // Periodically clean up expired entries
        if (expiryMap.size() % 100 == 0) {
            removeExpired();
        }
    }
    
    bool remove(const K& key) override {
        std::lock_guard<std::mutex> lock(expiryMutex);
        
        expiryMap.erase(key);
        return wrappedCache->remove(key);
    }
    
    size_t size() const override {
        std::lock_guard<std::mutex> lock(expiryMutex);
        return wrappedCache->size();
    }
    
    void clear() override {
        std::lock_guard<std::mutex> lock(expiryMutex);
        
        wrappedCache->clear();
        expiryMap.clear();
    }
    
    void removeAllExpired() {
        std::lock_guard<std::mutex> lock(expiryMutex);
        removeExpired();
    }
};
```

### Example Usage

```cpp
// Create an LRU cache with capacity of 100 items
auto lruCache = std::make_shared<LRUCache<std::string, std::string>>(100);

// Wrap it with expiration (default TTL of 1 hour)
ExpiringCache<std::string, std::string> cache(lruCache, std::chrono::hours(1));

// Add an item with default expiration (1 hour)
cache.put("key1", "value1");

// Add an item with custom expiration (5 minutes)
cache.put("key2", "value2", std::chrono::minutes(5));

// Get an item (returns nullopt if expired or not found)
auto value = cache.get("key1");
if (value) {
    std::cout << "Value: " << *value << std::endl;
}
```

### Decorator Pattern Explained

The Decorator pattern enables:

1. **Dynamic Extension**: The `ExpiringCache` decorator adds expiration functionality to any cache implementation
2. **Composition over Inheritance**: Functionality is added through composition rather than inheritance
3. **Open/Closed Principle**: New functionality can be added without modifying existing cache implementations
4. **Single Responsibility Principle**: Each class has a single responsibility (LRU eviction, expiration, etc.)

### Thread Safety Approach

- The LRU cache has its own mutex to protect the list and map
- The expiration decorator has a separate mutex for the expiry map
- This approach allows for fine-grained locking and better concurrency

### Time and Space Complexity

- **Get Operation**: O(1) average case with hash map
- **Put Operation**: O(1) average case (O(n) worst case for eviction)
- **Remove Operation**: O(1) average case
- **Space Complexity**: O(n) where n is the number of cache entries

### Extension Points

1. **Alternative Eviction Policies**: Implement LFU, FIFO, or other policies
2. **Persistence**: Add support for persisting cache to disk
3. **Event Notifications**: Add callbacks for cache events (hits, misses, evictions)
4. **Statistics and Metrics**: Track cache performance metrics
5. **Distributed Cache**: Extend to a distributed environment with synchronization

## 4. Logging Framework

### Core Requirements

- Support different logging levels (DEBUG, INFO, WARN, ERROR, etc.)
- Allow logging to multiple destinations (console, file, network, etc.)
- Provide a flexible formatting system
- Ensure thread safety for concurrent logging
- Support asynchronous logging to minimize application impact

### Design: Chain of Responsibility and Observer Patterns

The logging framework design combines Chain of Responsibility for log level filtering and Observer for multiple outputs:

```cpp
// Log Level enum
enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL,
    OFF
};

// Log Entry struct
struct LogEntry {
    LogLevel level;
    std::string message;
    std::string logger;
    std::chrono::system_clock::time_point timestamp;
    std::thread::id threadId;
    
    LogEntry(LogLevel lvl, std::string msg, std::string loggerName)
        : level(lvl), message(std::move(msg)), logger(std::move(loggerName)),
          timestamp(std::chrono::system_clock::now()), threadId(std::this_thread::get_id()) {}
};

// Observer interface for log appenders
class LogAppender {
public:
    virtual ~LogAppender() = default;
    virtual void append(const LogEntry& entry) = 0;
    virtual void setFormatter(std::function<std::string(const LogEntry&)> formatter) = 0;
};

// Console appender implementation
class ConsoleAppender : public LogAppender {
private:
    std::function<std::string(const LogEntry&)> formatter;
    std::mutex consoleMutex;
    
public:
    ConsoleAppender(std::function<std::string(const LogEntry&)> fmt = nullptr)
        : formatter(fmt ? fmt : &ConsoleAppender::defaultFormat) {}
    
    void append(const LogEntry& entry) override {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << (formatter ? formatter(entry) : defaultFormat(entry)) << std::endl;
    }
    
    void setFormatter(std::function<std::string(const LogEntry&)> fmt) override {
        formatter = fmt;
    }
    
    static std::string defaultFormat(const LogEntry& entry) {
        std::ostringstream oss;
        oss << "[" << LogLevelToString(entry.level) << "] "
            << "[" << entry.logger << "] "
            << entry.message;
        return oss.str();
    }
    
    static std::string LogLevelToString(LogLevel level) {
        switch (level) {
            case LogLevel::TRACE: return "TRACE";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO ";
            case LogLevel::WARN:  return "WARN ";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::FATAL: return "FATAL";
            case LogLevel::OFF:   return "OFF  ";
            default:              return "UNKN ";
        }
    }
};

// File appender implementation
class FileAppender : public LogAppender {
private:
    std::string filePath;
    std::ofstream fileStream;
    std::function<std::string(const LogEntry&)> formatter;
    std::mutex fileMutex;
    
public:
    FileAppender(const std::string& path, std::function<std::string(const LogEntry&)> fmt = nullptr)
        : filePath(path), formatter(fmt ? fmt : &FileAppender::defaultFormat) {
        fileStream.open(filePath, std::ios::app);
    }
    
    ~FileAppender() {
        if (fileStream.is_open()) {
            fileStream.close();
        }
    }
    
    void append(const LogEntry& entry) override {
        std::lock_guard<std::mutex> lock(fileMutex);
        if (fileStream.is_open()) {
            fileStream << (formatter ? formatter(entry) : defaultFormat(entry)) << std::endl;
            fileStream.flush();
        }
    }
    
    void setFormatter(std::function<std::string(const LogEntry&)> fmt) override {
        formatter = fmt;
    }
    
    static std::string defaultFormat(const LogEntry& entry) {
        auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << " "
            << "[" << ConsoleAppender::LogLevelToString(entry.level) << "] "
            << "[" << entry.logger << "] "
            << "[Thread-" << entry.threadId << "] "
            << entry.message;
        return oss.str();
    }
};

// Async appender using a background thread
class AsyncAppender : public LogAppender {
private:
    std::shared_ptr<LogAppender> wrappedAppender;
    std::queue<LogEntry> logQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;
    std::thread workerThread;
    bool running;
    
    void processLogs() {
        while (running) {
            std::vector<LogEntry> batch;
            
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCondition.wait(lock, [this] { return !running || !logQueue.empty(); });
                
                if (!running && logQueue.empty()) {
                    return;
                }
                
                // Process in batch for efficiency
                for (int i = 0; i < 100 && !logQueue.empty(); ++i) {
                    batch.push_back(logQueue.front());
                    logQueue.pop();
                }
            }
            
            for (const auto& entry : batch) {
                wrappedAppender->append(entry);
            }
        }
    }
    
public:
    AsyncAppender(std::shared_ptr<LogAppender> appender)
        : wrappedAppender(appender), running(true) {
        workerThread = std::thread(&AsyncAppender::processLogs, this);
    }
    
    ~AsyncAppender() {
        running = false;
        queueCondition.notify_one();
        
        if (workerThread.joinable()) {
            workerThread.join();
        }
    }
    
    void append(const LogEntry& entry) override {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push(entry);
        queueCondition.notify_one();
    }
    
    void setFormatter(std::function<std::string(const LogEntry&)> formatter) override {
        wrappedAppender->setFormatter(formatter);
    }
};

// Logger class - main interface for application code
class Logger {
private:
    std::string name;
    LogLevel level;
    std::vector<std::shared_ptr<LogAppender>> appenders;
    std::mutex loggerMutex;
    
public:
    Logger(const std::string& loggerName, LogLevel logLevel = LogLevel::INFO)
        : name(loggerName), level(logLevel) {}
    
    void addAppender(std::shared_ptr<LogAppender> appender) {
        std::lock_guard<std::mutex> lock(loggerMutex);
        appenders.push_back(appender);
    }
    
    void removeAppender(std::shared_ptr<LogAppender> appender) {
        std::lock_guard<std::mutex> lock(loggerMutex);
        appenders.erase(
            std::remove(appenders.begin(), appenders.end(), appender),
            appenders.end()
        );
    }
    
    void setLevel(LogLevel logLevel) {
        std::lock_guard<std::mutex> lock(loggerMutex);
        level = logLevel;
    }
    
    LogLevel getLevel() const {
        return level;
    }
    
    void log(LogLevel msgLevel, const std::string& message) {
        if (msgLevel < level) {
            return;  // Skip if message level is below logger level
        }
        
        LogEntry entry(msgLevel, message, name);
        
        std::lock_guard<std::mutex> lock(loggerMutex);
        for (const auto& appender : appenders) {
            appender->append(entry);
        }
    }
    
    // Convenience methods
    void trace(const std::string& message) { log(LogLevel::TRACE, message); }
    void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    void info(const std::string& message) { log(LogLevel::INFO, message); }
    void warn(const std::string& message) { log(LogLevel::WARN, message); }
    void error(const std::string& message) { log(LogLevel::ERROR, message); }
    void fatal(const std::string& message) { log(LogLevel::FATAL, message); }
};

// LogManager singleton - factory for loggers
class LogManager {
private:
    std::unordered_map<std::string, std::shared_ptr<Logger>> loggers;
    std::mutex managerMutex;
    
    LogManager() = default;
    
public:
    static LogManager& getInstance() {
        static LogManager instance;
        return instance;
    }
    
    std::shared_ptr<Logger> getLogger(const std::string& name) {
        std::lock_guard<std::mutex> lock(managerMutex);
        
        auto it = loggers.find(name);
        if (it != loggers.end()) {
            return it->second;
        }
        
        auto logger = std::make_shared<Logger>(name);
        loggers[name] = logger;
        return logger;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(managerMutex);
        loggers.clear();
    }
};

// Example usage
void loggingExample() {
    // Get a logger from the manager
    auto logger = LogManager::getInstance().getLogger("AppComponent");
    
    // Add console appender with default formatting
    auto consoleAppender = std::make_shared<ConsoleAppender>();
    logger->addAppender(consoleAppender);
    
    // Add async file appender with custom formatting
    auto fileAppender = std::make_shared<FileAppender>("app.log");
    auto asyncAppender = std::make_shared<AsyncAppender>(fileAppender);
    logger->addAppender(asyncAppender);
    
    // Log some messages
    logger->info("Application started");
    logger->debug("Debug information");
    logger->error("An error occurred: out of memory");
}
```

### Design Patterns Explained

The logging framework uses multiple design patterns:

1. **Observer Pattern**: Appenders observe and respond to log events
2. **Chain of Responsibility**: LogLevel filtering forms a chain of responsibility
3. **Decorator Pattern**: AsyncAppender decorates other appenders with asynchronous behavior
4. **Singleton Pattern**: LogManager provides a centralized access point for loggers
5. **Factory Method**: LogManager creates and manages Logger instances

### Thread Safety Approach

- Each appender has its own mutex for thread-safe logging
- The logger has a mutex to protect appender list modifications
- The async appender uses a producer-consumer pattern with a dedicated thread
- The log manager has a mutex to protect the logger map

### Time and Space Complexity

- **Log Operation**: O(a) where a is the number of appenders
- **Logger Lookup**: O(1) using the hash map
- **Asynchronous Logging**: O(1) for the caller (queue insertion)
- **Space Complexity**: O(n+m) where n is the number of loggers and m is the size of the log queue

### Extension Points

1. **Custom Appenders**: Add appenders for databases, cloud services, etc.
2. **Advanced Formatting**: Support pattern-based formatting
3. **Log Rotation**: Add support for time or size-based log rotation
4. **Filtering**: Add more sophisticated filtering based on logger hierarchy
5. **MDC (Mapped Diagnostic Context)**: Add support for contextual logging information

## 5. Object Pool

### Core Requirements

- Pre-allocate a pool of reusable objects to reduce allocation overhead
- Support get and release operations for object lifecycle management
- Ensure thread safety for concurrent access
- Implement configurable pool size and growth policies
- Add support for object validation and reset between uses

### Design: Factory Method and Singleton Patterns

The object pool design uses factory methods to create objects and manages their lifecycle:

```cpp
// Interface for object creation and reset
template <typename T>
class ObjectFactory {
public:
    virtual ~ObjectFactory() = default;
    virtual std::shared_ptr<T> createObject() = 0;
    virtual void resetObject(T& obj) = 0;
    virtual bool validateObject(const T& obj) = 0;
};

// Generic object pool implementation
template <typename T>
class ObjectPool {
private:
    std::queue<std::shared_ptr<T>> availableObjects;
    std::unordered_set<std::shared_ptr<T>> inUseObjects;
    std::shared_ptr<ObjectFactory<T>> factory;
    size_t minSize;
    size_t maxSize;
    size_t currentSize;
    std::mutex poolMutex;
    std::condition_variable poolCondition;
    
    bool expandPool() {
        if (currentSize >= maxSize) {
            return false;
        }
        
        auto newObj = factory->createObject();
        if (newObj) {
            availableObjects.push(newObj);
            currentSize++;
            return true;
        }
        
        return false;
    }
    
public:
    ObjectPool(std::shared_ptr<ObjectFactory<T>> objFactory, 
               size_t initialSize = 10, 
               size_t maxPoolSize = 100)
        : factory(objFactory), minSize(initialSize), maxSize(maxPoolSize), currentSize(0) {
        
        // Pre-allocate initial objects
        for (size_t i = 0; i < minSize; ++i) {
            expandPool();
        }
    }
    
    ~ObjectPool() {
        std::lock_guard<std::mutex> lock(poolMutex);
        
        // Clear all objects
        while (!availableObjects.empty()) {
            availableObjects.pop();
        }
        
        inUseObjects.clear();
        currentSize = 0;
    }
    
    // Get an object from the pool (or create a new one)
    std::shared_ptr<T> acquire(std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) {
        std::unique_lock<std::mutex> lock(poolMutex);
        
        // Wait for an available object
        if (timeout > std::chrono::milliseconds(0)) {
            bool success = poolCondition.wait_for(lock, timeout, [this] {
                return !availableObjects.empty() || currentSize < maxSize;
            });
            
            if (!success) {
                return nullptr;  // Timeout expired
            }
        }
        
        // Try to get an object from the pool
        if (availableObjects.empty()) {
            if (!expandPool()) {
                return nullptr;  // Cannot create more objects
            }
        }
        
        auto obj = availableObjects.front();
        availableObjects.pop();
        
        // Validate the object
        if (!factory->validateObject(*obj)) {
            // Object failed validation, create a new one
            obj = factory->createObject();
            if (!obj) {
                return nullptr;  // Failed to create a replacement
            }
        }
        
        inUseObjects.insert(obj);
        
        // Create a custom deleter that returns the object to the pool
        return std::shared_ptr<T>(obj.get(), [this, obj](T*) {
            this->release(obj);
        });
    }
    
    // Return an object to the pool
    void release(std::shared_ptr<T> obj) {
        std::lock_guard<std::mutex> lock(poolMutex);
        
        auto it = inUseObjects.find(obj);
        if (it != inUseObjects.end()) {
            // Reset the object state
            factory->resetObject(*obj);
            
            // Return to available queue
            availableObjects.push(obj);
            inUseObjects.erase(it);
            
            // Notify waiting threads
            poolCondition.notify_one();
        }
    }
    
    // Current pool stats
    size_t available() const {
        std::lock_guard<std::mutex> lock(poolMutex);
        return availableObjects.size();
    }
    
    size_t inUse() const {
        std::lock_guard<std::mutex> lock(poolMutex);
        return inUseObjects.size();
    }
    
    size_t totalSize() const {
        std::lock_guard<std::mutex> lock(poolMutex);
        return currentSize;
    }
};
```

### Example: Database Connection Pool

```cpp
// Database connection class
class DbConnection {
private:
    std::string connectionString;
    bool connected;
    
public:
    DbConnection(const std::string& connStr) : connectionString(connStr), connected(false) {}
    
    bool connect() {
        // Simulate connection establishment
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        connected = true;
        return connected;
    }
    
    bool disconnect() {
        connected = false;
        return true;
    }
    
    bool isConnected() const {
        return connected;
    }
    
    bool executeQuery(const std::string& query) {
        if (!connected) {
            return false;
        }
        
        // Simulate query execution
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return true;
    }
};

// Factory for database connections
class DbConnectionFactory : public ObjectFactory<DbConnection> {
private:
    std::string connectionString;
    
public:
    DbConnectionFactory(const std::string& connStr) : connectionString(connStr) {}
    
    std::shared_ptr<DbConnection> createObject() override {
        auto conn = std::make_shared<DbConnection>(connectionString);
        if (conn && conn->connect()) {
            return conn;
        }
        return nullptr;
    }
    
    void resetObject(DbConnection& obj) override {
        // Reset connection state if needed
        if (!obj.isConnected()) {
            obj.connect();
        }
    }
    
    bool validateObject(const DbConnection& obj) override {
        return obj.isConnected();
    }
};

// Connection pool manager (singleton)
class DbConnectionPool {
private:
    std::shared_ptr<ObjectPool<DbConnection>> pool;
    
    DbConnectionPool(const std::string& connectionString, size_t initialSize, size_t maxSize) {
        auto factory = std::make_shared<DbConnectionFactory>(connectionString);
        pool = std::make_shared<ObjectPool<DbConnection>>(factory, initialSize, maxSize);
    }
    
public:
    static DbConnectionPool& getInstance(const std::string& connectionString = "", 
                                        size_t initialSize = 5, 
                                        size_t maxSize = 20) {
        static DbConnectionPool instance(connectionString, initialSize, maxSize);
        return instance;
    }
    
    std::shared_ptr<DbConnection> getConnection(std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
        return pool->acquire(timeout);
    }
    
    size_t availableConnections() const {
        return pool->available();
    }
    
    size_t activeConnections() const {
        return pool->inUse();
    }
};
```

### Example Usage

```cpp
void databaseExample() {
    // Initialize the connection pool
    auto& connPool = DbConnectionPool::getInstance("host=localhost;user=admin;pwd=secret", 5, 20);
    
    // Get a connection from the pool
    auto conn = connPool.getConnection();
    if (conn) {
        // Use the connection
        conn->executeQuery("SELECT * FROM users");
        
        // Connection is automatically returned to the pool when shared_ptr goes out of scope
    }
    
    // Get multiple connections concurrently
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&connPool, i]() {
            auto conn = connPool.getConnection();
            if (conn) {
                conn->executeQuery("SELECT * FROM table" + std::to_string(i));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
}
```

### Factory Method Pattern Explained

The Factory Method pattern enables:

1. **Encapsulated Object Creation**: The factory encapsulates the logic for creating objects
2. **Lifecycle Management**: The factory also handles object validation and reset
3. **Customization**: Different factories can create different types of objects for the same pool
4. **Testability**: The factory can be mocked for testing

### Thread Safety Approach

- The object pool uses a mutex to protect its internal data structures
- A condition variable is used for waiting when the pool is empty
- The custom deleter ensures that objects are always returned to the pool
- Thread-safe acquire and release operations enable concurrent usage

### Time and Space Complexity

- **Acquire Operation**: O(1) when objects are available, O(1) for creation
- **Release Operation**: O(1) for returning objects to the pool
- **Space Complexity**: O(n) where n is the total number of objects in the pool

### Extension Points

1. **Dynamic Sizing**: Implement automatic pool resizing based on usage patterns
2. **Timeout Policies**: Add more sophisticated timeout and retry policies
3. **Monitoring and Metrics**: Track pool usage statistics over time
4. **Custom Allocation Strategies**: Different strategies for object allocation and eviction
5. **Object Lifecycle Policies**: Add policies for maximum object age or usage count

## Conclusion

These five low-level designs demonstrate key concepts and patterns that are essential for building robust, efficient, and maintainable systems:

1. **File System**: Shows the Composite pattern for hierarchical structures
2. **Rate Limiter**: Demonstrates the Strategy pattern for interchangeable algorithms
3. **Thread-Safe Cache**: Illustrates the Decorator pattern for extending functionality
4. **Logging Framework**: Combines Observer and Chain of Responsibility patterns for flexible event handling
5. **Object Pool**: Uses Factory Method pattern for efficient resource management

All designs prioritize:
- Thread safety for concurrent access
- Clean separation of concerns
- Extensibility through well-defined interfaces
- Performance optimization through appropriate data structures
- Robust error handling and state management

These designs serve as a solid foundation for tackling technical interviews at MAANG companies.

