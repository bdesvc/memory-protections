# memory-protections
A memory protections library for C++
with advanced kernel and anti dumping techniques

# How to use
You simply initialize the struct and call it as so

![api](https://i.imgur.com/xjnwnPv.png)

# Features

We have shared kernel data detection to check for kernel communications with `Shared Memory`
And advanced antidebug that increases size of the memory region and erases PE headers

# Help
If you're trying to aggresively protect an application we recommend you use the included xor library!
