# APIFuzzing
Fuzz API data ( json input supported)

Now which ever values are to be targeted for fuzzing shall need to be
surrounded by dollar.
e.g.
1 -> '$1$'
'hi' -> '$hi$'
False -> '$False$'

For each iteration only one of the target value will be replaced by a
value from mal data
the other target value will retain default values.
