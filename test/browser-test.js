

class Tester {
    constructor() {
        this.count_errors = 0
        this.count_pass = 0
    }

    is(a,b) {
        if ( a === b ) {
            this.count_pass++
            console.log("PASS is")
        } else {
            this.count_errors++
            console.log("FAIL is")
        }
        return a === b
    }

    false(b) {
        if ( false === b ) {
            this.count_pass++
            console.log("PASS false")
        } else {
            this.count_errors++
            console.log("FAIL false")
        }
        return(b===false)
    }

    true(b) {
        if ( true === b ) {
            this.count_pass++
            console.log("PASS false")
        } else {
            this.count_errors++
            console.log("FAIL false")
        }
        return(b===true)
    }
}



export function make_test () {
    return new Tester()
}


export function report(tester) {
    console.log("PASSED " + tester.count_pass + " tests")
    console.log("FAILED " + tester.count_errors + " tests")
    return ["PASSED " + tester.count_pass + " tests","FAILED " + tester.count_errors + " tests"]
}