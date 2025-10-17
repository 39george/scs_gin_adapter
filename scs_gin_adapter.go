package scs_gin_adapter

import (
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/gin-gonic/gin"
)

// GinAdapter represents the session adapter.
type GinAdapter struct {
	sm *scs.SessionManager
}

// New returns a new GinAdapter instance that embeds the original SCS session manager.
func New(s *scs.SessionManager) *GinAdapter {
	return &GinAdapter{s}
}

// LoadAndSave provides a Gin middleware which automatically loads and saves session
// data for the current request, and communicates the session token to and from
// the client in a cookie.
func (ga *GinAdapter) LoadAndSave(ginCtx *gin.Context) {
	respWriter := ginCtx.Writer
	req := ginCtx.Request

	var token string
	cookie, err := req.Cookie(ga.sm.Cookie.Name)
	if err == nil {
		token = cookie.Value
	}

	ctx, err := ga.sm.Load(req.Context(), token)
	if err != nil {
		ga.sm.ErrorFunc(respWriter, req, err)
		return
	}

	sessionReq := req.WithContext(ctx)
	respWriter.Header().Add("Vary", "Cookie")

	ginCtx.Request = sessionReq
	ginCtx.Next()
}

// Put adds a key and corresponding value to the session data. Any existing
// value for the key will be replaced. The session data status will be set to
// Modified.
func (ga *GinAdapter) Put(ctx *gin.Context, key string, val interface{}) {
	ga.sm.Put(ctx.Request.Context(), key, val)
	tok, exp, _ := ga.sm.Commit(ctx.Request.Context())
	ga.sm.WriteSessionCookie(ctx.Request.Context(), ctx.Writer, tok, exp)
}

// Get returns the value for a given key from the session data. The return
// value has the type interface{} so will usually need to be type asserted
// before you can use it. For example:
//
//	foo, ok := session.Get(r, "foo").(string)
//	if !ok {
//		return errors.New("type assertion to string failed")
//	}
//
// Also see the GetString(), GetInt(), GetBytes() and other helper methods which
// wrap the type conversion for common types.
func (ga *GinAdapter) Get(ctx *gin.Context, key string) interface{} {
	val := ga.sm.Get(ctx.Request.Context(), key)
	ga.sm.Commit(ctx.Request.Context())
	return val
}

// Remove deletes the given key and corresponding value from the session data.
// The session data status will be set to Modified. If the key is not present
// this operation is a no-op.
func (ga *GinAdapter) Remove(ctx *gin.Context, key string) {
	ga.sm.Remove(ctx.Request.Context(), key)
	tok, exp, _ := ga.sm.Commit(ctx.Request.Context())
	ga.sm.WriteSessionCookie(ctx.Request.Context(), ctx.Writer, tok, exp)
	return
}

// Destroy deletes the session data from the session store and sets the session
// status to Destroyed. Any further operations in the same request cycle will
// result in a new session being created.
func (ga *GinAdapter) Destroy(ctx *gin.Context) error {
	err := ga.sm.Destroy(ctx.Request.Context())
	if err != nil {
		return err
	}
	ga.sm.WriteSessionCookie(ctx.Request.Context(), ctx.Writer, "", time.Time{})
	return nil
}

// RenewToken updates the session data to have a new session token while
// retaining the current session data. The session lifetime is also reset and
// the session data status will be set to Modified.
//
// The old session token and accompanying data are deleted from the session store.
//
// To mitigate the risk of session fixation attacks, it's important that you call
// RenewToken before making any changes to privilege levels (e.g. login and
// logout operations). See https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Session_Management_Cheat_Sheet.md#renew-the-session-id-after-any-privilege-level-change
// for additional information.
func (ga *GinAdapter) RenewToken(ctx *gin.Context) error {
	err := ga.sm.RenewToken(ctx.Request.Context())
	if err != nil {
		return err
	}
	tok, exp, _ := ga.sm.Commit(ctx.Request.Context())
	ga.sm.WriteSessionCookie(ctx.Request.Context(), ctx.Writer, tok, exp)
	return nil
}

// RememberMe controls whether the session cookie is persistent (i.e  whether it
// is retained after a user closes their browser). RememberMe only has an effect
// if you have set SessionManager.Cookie.Persist = false (the default is true) and
// you are using the standard LoadAndSave() middleware.
func (ga *GinAdapter) RememberMe(ctx *gin.Context, val bool) {
	ga.sm.RememberMe(ctx.Request.Context(), val)
	tok, exp, _ := ga.sm.Commit(ctx.Request.Context())
	ga.sm.WriteSessionCookie(ctx.Request.Context(), ctx.Writer, tok, exp)
}

// GetString returns the string value for a given key from the session data.
// The zero value for a string ("") is returned if the key does not exist or the
// value could not be type asserted to a string.
func (ga *GinAdapter) GetString(ctx *gin.Context, key string) string {
	val := ga.sm.GetString(ctx.Request.Context(), key)
	tok, exp, _ := ga.sm.Commit(ctx.Request.Context())
	ga.sm.WriteSessionCookie(ctx.Request.Context(), ctx.Writer, tok, exp)
	return val
}
