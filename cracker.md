# Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`struct `[`_ChildDescriptor`](#struct___child_descriptor) | 
`struct `[`FoundPwd`](#struct_found_pwd) | 

# struct `_ChildDescriptor` 

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public int `[`read_fd`](#struct___child_descriptor_1a949927e1a897bedc3d324e4c9462559b) | 
`public int `[`write_fd`](#struct___child_descriptor_1a1a513611fd735d73fa2a618cc67858da) | 
`public pid_t `[`pid`](#struct___child_descriptor_1aeb889d95361667903aa36c587d5eec28) | 
`public int `[`err_no`](#struct___child_descriptor_1a591099ba2a0487bc6d6cf3ded4daa1f6) | 

## Members

#### `public int `[`read_fd`](#struct___child_descriptor_1a949927e1a897bedc3d324e4c9462559b) 

#### `public int `[`write_fd`](#struct___child_descriptor_1a1a513611fd735d73fa2a618cc67858da) 

#### `public pid_t `[`pid`](#struct___child_descriptor_1aeb889d95361667903aa36c587d5eec28) 

#### `public int `[`err_no`](#struct___child_descriptor_1a591099ba2a0487bc6d6cf3ded4daa1f6) 

# struct `FoundPwd` 

```
struct FoundPwd
  : public std::exception
```  

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public const char * `[`pwd`](#struct_found_pwd_1ad52abddfd3566389e1d0ce14a94fc785) | 
`public inline  `[`FoundPwd`](#struct_found_pwd_1aedbb7340db847370d7bdcfe41685dfe9)`()` | 
`public inline  `[`FoundPwd`](#struct_found_pwd_1a835d38f8b2e286cb63ecc8037667eb40)`(const char * pwd)` | 
`public inline const char * `[`what`](#struct_found_pwd_1a86f58b428679f85be81c10e5f56875d0)`() const` | 

## Members

#### `public const char * `[`pwd`](#struct_found_pwd_1ad52abddfd3566389e1d0ce14a94fc785) 

#### `public inline  `[`FoundPwd`](#struct_found_pwd_1aedbb7340db847370d7bdcfe41685dfe9)`()` 

#### `public inline  `[`FoundPwd`](#struct_found_pwd_1a835d38f8b2e286cb63ecc8037667eb40)`(const char * pwd)` 

#### `public inline const char * `[`what`](#struct_found_pwd_1a86f58b428679f85be81c10e5f56875d0)`() const` 

Generated by [Moxygen](https://sourcey.com/moxygen)