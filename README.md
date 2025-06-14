# JWT Auth (Golang)

> A JWT authentication package providing both Access Token and Refresh Token mechanisms, featuring fingerprint recognition, Redis storage, and automatic refresh functionality.<br>
> Node.js version can be found [here](https://github.com/pardnchiu/nodejs-jwt-auth)

[![version](https://img.shields.io/github/v/tag/pardnchiu/golang-jwt-auth)](https://github.com/pardnchiu/golang-jwt-auth/releases)

## Features

- ### Dual Token System
  - Access Token (short-lived, default 15 minutes) + Refresh Token (long-lived, default 7 days)
  - Automatic token refresh without re-login
  - ES256 algorithm (Elliptic Curve Digital Signature) for high security
- ### Device Fingerprinting
  - Generate unique fingerprints based on user agent, device ID, OS, and browser
  - Prevent token abuse across different devices
  - Automatic device type detection (desktop, mobile, tablet)
  - Persistent device ID tracking with automatic cookie management
- ### Security Protection
  - Token revocation: Add access tokens to blacklist on logout
  - Version control: Prevent replay attacks, auto-generate new ID after 5 refreshes by default
  - Smart refresh: Auto-regenerate based on remaining TTL (default under 50%)
  - Concurrency protection: Redis lock mechanism prevents concurrent refresh conflicts
- ### Zero Configuration
  - Auto-generate ECDSA key pairs on first startup if not provided
  - Multiple authentication methods: Cookie, Bearer Token, custom headers
  - Flexible deployment: Support for development/testing/production environments
  - Middleware support: Gin and standard HTTP middleware

## Dependencies

- [github.com/gin-gonic/gin](https://github.com/gin-gonic/gin)
- [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt/v5)
- [github.com/redis/go-redis/v9](https://github.com/redis/go-redis/v9)

## Usage

- ### Installation
  ```bash
  go get github.com/pardnchiu/golang-jwt-auth
  ```
- ### Minimal Configuration
  ```go
  package main

  import (
    "log"

    "github.com/pardnchiu/golang-jwt-auth"
  )

  func main() {
    // Minimal configuration - keys will be auto-generated
    config := &golangJwtAuth.Config{
        Redis: golangJwtAuth.Redis{
            Host: "localhost",
            Port: 6379,
            DB:   0,
        },
    }

    jwtAuth, err := golangJwtAuth.New(config)
    if err != nil {
        log.Fatal("Initialization failed:", err)
    }
    defer jwtAuth.Close()
    
    // Start using...
  }
  ```  
- ### Complete Configuration Example
  ```go
  type Config struct {
    // Redis connection configuration (required)
    Redis Redis {
        Host     string  // Redis host address (required)
        Port     int     // Redis port (required)
        Password string  // Redis password (default: "")
        DB       int     // Redis database number (required)
    }
    
    // User authentication callback (optional)
    CheckAuth func(Auth) (bool, error)  // User authentication function (default: nil)
    
    // File path configuration (optional)
    File *File {
        PrivateKeyPath string  // Private key file path (default: "")
        PublicKeyPath  string  // Public key file path (default: "")
    }
    
    // Log configuration (optional)
    Log *Log {
        Path    string  // Log file path (default: "./logs/golangJwtAuth")
        Stdout  bool    // Whether to output to stdout (default: false)
        MaxSize int64   // Maximum log file size (default: 16777216 = 16MB)
    }
    
    // System parameter configuration (optional)
    Option *Option {
        PrivateKey           string        // Private key content (default: "")
        PublicKey            string        // Public key content (default: "")
        AccessTokenExpires   time.Duration // Access Token expiration (default: 15 * time.Minute)
        RefreshIdExpires     time.Duration // Refresh ID expiration (default: 7 * 24 * time.Hour)
        AccessTokenCookieKey string        // Access Token Cookie name (default: "access_token")
        RefreshIdCookieKey   string        // Refresh ID Cookie name (default: "refresh_id")
        MaxVersion           int           // Maximum refresh version count (default: 5)
        RefreshTTL           float64       // Refresh TTL threshold (default: 0.5)
    }
    
    // Cookie security configuration (optional)
    Cookie *Cookie {
        Domain   *string        // Cookie domain (default: nil)
        Path     *string        // Cookie path (default: nil, uses "/")
        SameSite *http.SameSite // SameSite attribute (default: nil, uses Lax)
        Secure   *bool          // HTTPS only transmission (default: nil, uses false)
        HttpOnly *bool          // Disable JavaScript access (default: nil, uses true)
    }
  }
  ```

## API Usage Guide

- ### Create - `Create()`
  ```go
  func loginHandler(jwtAuth *golangJwtAuth.JWTAuth) http.HandlerFunc {
      return func(w http.ResponseWriter, r *http.Request) {
          // After validating login credentials...
          
          userData := &golangJwtAuth.Auth{
              ID:        "user123",
              Name:      "John Doe",
              Email:     "john@example.com",
              Thumbnail: "avatar.jpg",
              Role:      "user",
              Level:     1,
              Scope:     []string{"read", "write"},
          }

          result := jwtAuth.Create(w, r, userData)
          if !result.Success {
              w.WriteHeader(result.StatusCode)
              json.NewEncoder(w).Encode(map[string]string{
                  "error": result.Error,
              })
              return
          }

          // Automatically set cookies and return tokens
          json.NewEncoder(w).Encode(map[string]interface{}{
              "success":    true,
              "token":      result.Token.Token,
              "refresh_id": result.Token.RefreshId,
              "user":       result.Data,
          })
      }
  }
  ```
- ### Verify - `Verify()`
  ```go
  func protectedHandler(jwtAuth *golangJwtAuth.JWTAuth) http.HandlerFunc {
      return func(w http.ResponseWriter, r *http.Request) {
          result := jwtAuth.Verify(w, r)
          
          if !result.Success {
              w.WriteHeader(result.StatusCode)
              json.NewEncoder(w).Encode(map[string]string{
                  "error":     result.Error,
                  "error_tag": result.ErrorTag,
              })
              return
          }

          // Use authenticated user data
          user := result.Data
          json.NewEncoder(w).Encode(map[string]interface{}{
              "message": "Protected resource access successful",
              "user":    user,
          })
      }
  }
  ```
- ### Revoke - `Revoke()`
  ```go
  func logoutHandler(jwtAuth *golangJwtAuth.JWTAuth) http.HandlerFunc {
      return func(w http.ResponseWriter, r *http.Request) {
          result := jwtAuth.Revoke(w, r)
          if !result.Success {
              w.WriteHeader(result.StatusCode)
              json.NewEncoder(w).Encode(map[string]string{
                  "error":     result.Error,
                  "error_tag": result.ErrorTag,
              })
              return
          }

          json.NewEncoder(w).Encode(map[string]string{
              "message": "Successfully logged out",
          })
      }
  }
  ```
- ### Middleware
  - #### Gin Framework
    ```go
    package main

    import (
        "github.com/gin-gonic/gin"
        "github.com/pardnchiu/golang-jwt-auth"
    )

    func main() {
        // Initialize jwtAuth...
        
        r := gin.Default()
        
        // Protected route group
        protected := r.Group("/api/protected")
        protected.Use(jwtAuth.GinMiddleware())
        {
            protected.GET("/profile", func(c *gin.Context) {
                // Get user data from Context
                user, exists := golangJwtAuth.GetAuthDataFromGinContext(c)
                if !exists {
                    c.JSON(500, gin.H{"error": "Unable to retrieve user data"})
                    return
                }
                
                c.JSON(200, gin.H{"user": user})
            })
        }
        
        r.Run(":8080")
    }
    ```
  - #### Standard HTTP
    ```go
    package main

    import (
        "net/http"
        "github.com/pardnchiu/golang-jwt-auth"
    )

    func main() {
        // Initialize jwtAuth...
        
        mux := http.NewServeMux()
        
        mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
            // Get user data from Request Context
            user, exists := golangJwtAuth.GetAuthDataFromHTTPRequest(r)
            if !exists {
                http.Error(w, "Unable to retrieve user data", http.StatusInternalServerError)
                return
            }
            
            json.NewEncoder(w).Encode(map[string]interface{}{"user": user})
        })
        
        // Apply middleware
        server := &http.Server{
            Addr:    ":8080",
            Handler: jwtAuth.HTTPMiddleware(mux),
        }
        
        server.ListenAndServe()
    }
    ```

## Security Features

- **Device Fingerprinting**: Generate unique fingerprints based on user agent, device ID, OS, browser, and device type with persistent tracking
- **Token Revocation**: Add tokens to blacklist on logout
- **Automatic Expiration**: Support TTL auto-cleanup for expired tokens
- **Version Control**: Track refresh token versions to prevent replay attacks
- **Fingerprint Verification**: Ensure tokens can only be used on the same device/browser
- **Auto Key Generation**: Automatically generate secure ECDSA key pairs if not provided

## Automatic Token Refresh Mechanism

The system automatically refreshes tokens in the following situations:

1. **Access Token Expired** - Automatically update using refresh token
2. **Version Limit Reached** - Regenerate refresh ID (default 5 times)
3. **TTL Below Threshold** - Auto-regenerate based on remaining TTL (default under 50%)

New tokens are returned via:
- **HTTP Headers**: `X-New-Access-Token`, `X-New-Refresh-ID`
- **Cookies**: Automatic updates
- **Concurrency Safe**: Redis locks prevent duplicate refreshes

## Supported Authentication Methods

| Method | Format | Priority |
|--------|--------|----------|
| **Custom Fingerprint** | `X-Device-FP: <fingerprint>` | 1 |
| **Refresh ID** | `X-Refresh-ID: <refresh_id>` | 1 |
| **Device ID** | `X-Device-ID: <device_id>` | 1 |
| **Bearer Token** | `Authorization: Bearer <token>` | 1 |
| **Cookie** | Automatically read configured cookie names | 2 |

## Error Handling

All major methods return a `JWTAuthResult` structure:

```go
type JWTAuthResult struct {
    StatusCode int          `json:"status_code"`         // HTTP status code
    Success    bool         `json:"success"`             // Whether operation succeeded
    Data       *Auth        `json:"data,omitempty"`      // User data
    Token      *TokenResult `json:"token,omitempty"`     // Token information
    Error      string       `json:"error,omitempty"`     // Error message
    ErrorTag   string       `json:"error_tag,omitempty"` // Error classification tag
}
```

### Error Tags

- `data_missing` - Required data not provided
- `data_invalid` - Invalid data format
- `unauthorized` - Authentication failed
- `revoked` - Token has been revoked
- `not_found` - Resource not found
- `not_matched` - Data mismatch
- `failed_to_update` - Update operation failed
- `failed_to_create` - Creation operation failed
- `failed_to_sign` - Token signing failed
- `failed_to_store` - Storage operation failed
- `failed_to_get` - Retrieval operation failed

## License

This source code project is licensed under the [MIT](https://github.com/pardnchiu/FlexPlyr/blob/main/LICENSE) license.

## Creator

<img src="https://avatars.githubusercontent.com/u/25631760" align="left" width="96" height="96" style="margin-right: 0.5rem;">

<h4 style="padding-top: 0">邱敬幃 Pardn Chiu</h4>

<a href="mailto:dev@pardn.io" target="_blank">
    <img src="https://pardn.io/image/email.svg" width="48" height="48">
</a> <a href="https://linkedin.com/in/pardnchiu" target="_blank">
    <img src="https://pardn.io/image/linkedin.svg" width="48" height="48">
</a>

***

©️ 2025 [邱敬幃 Pardn Chiu](https://pardn.io)