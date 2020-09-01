# generatePass.py

    Strong password generator in Python.


## Help

    generatePass.py
                    Without argument it generates an 'unique' 
                    strong password.
                    It stores a pseudo-encrypted version of it,
                    so it can control to no-repeat.

    -h|--help|-?
                    Shows this help.

            -C      Clear storage.
            -R      Review storage.
            -X      Extended storage list.

            -g      Generate Password
                    
            -n1     At least 1 number
            -l1     At least 1 lowercase character
            -u1     At least 1 uppercase character
            -s1     At least 1 symbol
            
            -m8     Minimum length 8
            -M32    Maximum length 32
            
            -L      Include Lowercase Characters
            -U      Include Uppercase Characters
            -N      Include Numeric Characters
            -S      Include Symbols

            --L     Do Not Include Lowercase Characters
            --U     Do Not Include Uppercase Characters
            --N     Do Not Include Numeric Characters
            --S     Do Not Include Symbols
            
            -v      Verbose on
            
            metfar@gmail.com    
                                    
## Examples
<pre>
 $ ./generatePass.py -R
                    TIME    HASH
                    ----    ----
     2020-09-01 17:46:15    !1a+620T1:x
     2020-09-01 17:52:11    jZeCOIIWy#y_8*
     2020-09-01 18:03:52    =px@3d*gqQ
     2020-09-01 18:04:24    277064696291951317158475702013
     2020-09-01 18:04:47    19339723
     2020-09-01 18:05:03    76898049

 $ ./generatePass.py -X
                    TIME    HASH [minLen,maxLen,atLeastLow,atlUpp,atlSym,atlNum,lowers,uppers,syms,nums]
                    ----    ---- [···]
     2020-09-01 17:46:15    !1a+620T1:x [8, 32, 1, 1, 1, 5, True, True, True, True]
     2020-09-01 17:52:11    jZeCOIIWy#y_8* [8, 32, 1, 1, 1, 1, True, True, True, True]
     2020-09-01 18:03:52    =px@3d*gqQ [8, 32, 1, 1, 1, 1, True, True, True, True]
     2020-09-01 18:04:24    277064696291951317158475702013 [8, 32, 1, 1, 1, 1, False, False, False, True]
     2020-09-01 18:04:47    19339723 [8, 8, 1, 1, 1, 1, False, False, False, True]
     2020-09-01 18:05:03    76898049 [8, 8, 1, 1, 1, 1, False, False, False, True]

 $ ./generatePass.py -g
     -4ouc_2_SwsR&4@tln+k1:lfA#id_

 $ ./generatePass.py -X
                    TIME    HASH [minLen,maxLen,atLeastLow,atlUpp,atlSym,atlNum,lowers,uppers,syms,nums]
                    ----    ---- [···]
     2020-09-01 17:46:15    !1a+620T1:x [8, 32, 1, 1, 1, 5, True, True, True, True]
     2020-09-01 17:52:11    jZeCOIIWy#y_8* [8, 32, 1, 1, 1, 1, True, True, True, True]
     2020-09-01 18:03:52    =px@3d*gqQ [8, 32, 1, 1, 1, 1, True, True, True, True]
     2020-09-01 18:04:24    277064696291951317158475702013 [8, 32, 1, 1, 1, 1, False, False, False, True]
     2020-09-01 18:04:47    19339723 [8, 8, 1, 1, 1, 1, False, False, False, True]
     2020-09-01 18:05:03    76898049 [8, 8, 1, 1, 1, 1, False, False, False, True]
     2020-09-01 18:21:20    #9bhp*7*FjfE=9:gya%x6@ysN-vq* [8, 32, 1, 1, 1, 1, True, True, True, True]
        
</pre>

## Repository

  - Full project <https://github.com/metfar/generatePass.py>
  
  
## License

  Copyright 2020 William Martinez Bas <metfar@gmail.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
  MA 02110-1301, USA.

#Thanks!
