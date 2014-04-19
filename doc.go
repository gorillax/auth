// Copyright 2014 http://github.com/bennAH. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*

Basic / Extremely simple web application authentication built on top of the Gorilla toolkit (hence, the gorillax).

Not really well structured, nor well tested. Use only if extremely brave.

Suggested improvements if interested:
-	fix any bugs
-	test cases
-	Seperate AuthManager to a new struct: only concerned about SecuredURLs, sessionName, PasswordEncoder & UserDetailsService
-	Create a new WebManager struct (or thing of something more clever) that wraps the AuthManager, Router, Store & AccessDeniedHanlder

Larger improvements
-	implement http request filters on top of gorilla mux
-	separate filter functionality into seperate package
-	implement authentication as a one/set of filter(s)
-	allow user registered filters
*/

package auth