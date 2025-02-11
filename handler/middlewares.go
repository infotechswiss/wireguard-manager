package handler

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// ContentTypeJson is middleware that ensures the request's Content-Type header
// starts with "application/json". This helps mitigate CSRF attacks by rejecting
// requests that do not explicitly signal a JSON payload.
func ContentTypeJson(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		contentType := c.Request().Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				Success: false,
				Message: "Only JSON allowed",
			})
		}
		return next(c)
	}
}
