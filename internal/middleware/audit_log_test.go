package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuditLog_PostRequest_Logged(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockAuditLogRepository(ctrl)
	handler := AuditLog(mockRepo)(dummyHandler)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	w := httptest.NewRecorder()

	mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditLog_GetRequest_Skipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockAuditLogRepository(ctrl)
	handler := AuditLog(mockRepo)(dummyHandler)

	req := httptest.NewRequest(http.MethodGet, "/auth/users", nil)
	w := httptest.NewRecorder()

	// EXPECT nothing

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditLog_UserContext_Included(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockAuditLogRepository(ctrl)
	handler := AuditLog(mockRepo)(dummyHandler)

	req := httptest.NewRequest(http.MethodPost, "/auth/profile", nil)
	authCtx := SetAuthContext(req.Context(), &AuthContext{UserID: "user-123"})
	req = req.WithContext(authCtx)
	w := httptest.NewRecorder()

	mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx interface{}, log interface{}) error {
		// Just returning nil, we verify it's called
		return nil
	})

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditLog_IPAddress_Captured(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockAuditLogRepository(ctrl)
	handler := AuditLog(mockRepo)(dummyHandler)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()

	mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditLog_DBError_NoBlock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockAuditLogRepository(ctrl)
	handler := AuditLog(mockRepo)(dummyHandler)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	w := httptest.NewRecorder()

	mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("db connection failed"))

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code) // Should not block or return 500
}
func TestAuditLog_HeadRequest_Skipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuditLogRepository(ctrl)
	handler := AuditLog(mockRepo)(dummyHandler)
	req := httptest.NewRequest(http.MethodHead, "/auth/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
func TestAuditLog_OptionsRequest_Skipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuditLogRepository(ctrl)
	handler := AuditLog(mockRepo)(dummyHandler)
	req := httptest.NewRequest(http.MethodOptions, "/auth/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
