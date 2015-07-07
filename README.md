# Cvss - CVSS calculator for Go

Ccvss is a Go library, which can be used to calculate CVSS scores from a string metric. 
For instance, an ugly and hard to read string like **"AV:N/AC:L/Au:N/C:N/I:N/A:C"** results in a calculated score of **7.8**. Much easier to read and to perform caluclation on.
 
For more information about the CVSS metric and definition as well as how the calculation is done in details, please see the [cvss v2 guide](https://www.first.org/cvss/v2/guide)

# Caveats

This package is WIP. At the time, only CVSS version 2 is supported, and only the base metric can be calculated. This is mainly based on the fact, that this package was developed for this very purpose. Anyhow, temporal and environmental metrics are planned to be integrated as well as CVSS version 3. 
