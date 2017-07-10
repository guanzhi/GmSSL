# About SM standard implementation

This is only a standard implementation of the SM.

In the standard implementation, it uses the **MIRACL** library. **MIRACL** (Multiprecision Integer and Rational Arithmetic Crytographic Library) is a C software library. See also [About the MIRACL Crypto SDK](https://libraries.docs.miracl.com/miracl-user-manual/about).

Also, you can download the source code in the Github. Here is a reference link. [Github MIRACL](https://github.com/miracl/MIRACL).

What's more, when you want test it and compile locally, you need add *-lm* option to solve some math functions problems like *ceil* in the code.