# APIFuzzing
Fuzz API data ( json input supported)

There are two libraries : UtilsLibFuzzing_v1 and UtilsLibFuzzing_v2

UtilsLibFuzzing_v1:

This traversers all the keys and replaces each with data from fuzzdb in each iteration and only one key in each iteration

UtilsLibFuzzing_v2
Now which ever values are to be targeted for fuzzing shall need to be
surrounded by dollar.
e.g.
1 -> '$1$'
'hi' -> '$hi$'
False -> '$False$'

For each iteration only one of the target value will be replaced by a
value from mal data
the other target value will retain default values.
