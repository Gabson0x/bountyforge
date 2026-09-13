# FV-MOV-5: Arithmetic and Type Safety

Move's integer-only arithmetic, silent bitwise overflow, and unsafe narrowing casts are responsible for multiple multi-million dollar exploits. This category covers every class of numeric bug including the Cetus $223M bitwise shift vector.

## Cases

- [fv-mov-5-cl1-bitwise-and-custom-math.md](fv-mov-5-cl1-bitwise-and-custom-math.md) - Bitwise left-shift overflow and custom math library edge cases
- [fv-mov-5-cl2-division-and-underflow.md](fv-mov-5-cl2-division-and-underflow.md) - Division before multiplication, division by zero, integer underflow
- [fv-mov-5-cl3-cast-truncation.md](fv-mov-5-cl3-cast-truncation.md) - Narrowing casts (u128 → u64) silently truncate without abort
- [fv-mov-5-cl4-rounding-and-constants.md](fv-mov-5-cl4-rounding-and-constants.md) - Rounding direction, vault inflation, wrong constant values

## Key Vectors

V61, V62, V63, V64, V65, V66, V67, V68, V69, V90, V98, V135, V136, V137, V138, V139
