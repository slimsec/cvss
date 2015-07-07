# Cvss - CVSS calculator for Go #

**Documentation:** [![GoDoc](https://godoc.org/github.com/slimsec/cvss?status.svg)](https://godoc.org/github.com/slimsec/cvss)

cvss is a Go library, which can be used to calculate CVSS scores from a string metric. 
For instance, an ugly and hard to read string like **"AV:N/AC:L/Au:N/C:N/I:N/A:C"** results in a calculated score of **7.8**. Much easier to read and to perform calculation on.
 
For more information about the CVSS metric and definition as well as how the calculation is done in details, please see the [cvss v2 guide](https://www.first.org/cvss/v2/guide)

## Usage ##

Import the library like this:
```bash 
go get github.com/slimsec/cvss
```


To calculate the cvss base score from a cvss, import the library and use the CalculateBaseScore function:

```go
package main

import (
  "fmt"
  "log"

  "github.com/slimsec/cvss"
)

func main() {
  score, err := cvss.CalculateBaseScore("AV:N/AC:L/Au:N/C:N/I:N/A:C", 2)
  if err != nil {
    log.Fatal(err)
  }

  fmt.Printf("CVSS score is: %0.1f\n", score)
}
```

## Caveats ##

This package is WIP. At the time, only CVSS version 2 is supported, and only the base metric can be calculated. This is mainly based on the fact, that this package was developed for this very purpose. Anyhow, temporal and environmental metrics are planned to be integrated as well as CVSS version 3. 
