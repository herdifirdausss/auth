package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type RiskService interface {
	AnalyzeLoginRisk(ctx context.Context, userID string, ip string, fingerprint string) (*model.RiskAssessment, error)
}

type RiskServiceImpl struct {
	userRepo          repository.UserRepository
	trustedDeviceRepo repository.TrustedDeviceRepository
	logger            *slog.Logger
}

func NewRiskService(userRepo repository.UserRepository, trustedDeviceRepo repository.TrustedDeviceRepository, logger *slog.Logger) RiskService {
	return &RiskServiceImpl{
		userRepo:          userRepo,
		trustedDeviceRepo: trustedDeviceRepo,
		logger:            logger,
	}
}

func (s *RiskServiceImpl) AnalyzeLoginRisk(ctx context.Context, userID string, ip string, fingerprint string) (*model.RiskAssessment, error) {
	assessment := &model.RiskAssessment{
		Level:   model.RiskLow,
		Reasons: []string{},
		Score:   0,
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// 1. Check if it's a New Device
	if fingerprint != "" {
		td, err := s.trustedDeviceRepo.FindByUserAndFingerprint(ctx, userID, fingerprint)
		if err != nil && !s.isNoRows(err) {
			return nil, err
		}
		if td == nil {
			assessment.Reasons = append(assessment.Reasons, "Login from a new device")
			assessment.Score += 30
		}
	} else {
		assessment.Reasons = append(assessment.Reasons, "No device fingerprint provided")
		assessment.Score += 20
	}

	// 2. Detect Impossible Travel (Basic Implementation)
	if user.LastLoginAt != nil && user.LastLoginIP != nil {
		if *user.LastLoginIP != ip {
			// In a real world, we would use GeoIP here to check distance.
			// For now, any IP change within a short time is a minor risk.
			if time.Since(*user.LastLoginAt) < 1*time.Hour {
				assessment.Reasons = append(assessment.Reasons, "Potential impossible travel (IP changed rapidly)")
				assessment.Score += 40
			} else {
				assessment.Score += 10
			}
		}
	}

	// Final Level Assessment
	if assessment.Score >= 70 {
		assessment.Level = model.RiskHigh
	} else if assessment.Score >= 30 {
		assessment.Level = model.RiskMedium
	}

	return assessment, nil
}

func (s *RiskServiceImpl) isNoRows(err error) bool {
	// Simple check, in reality it should check for specific pgx/sql error
	return err != nil && (err.Error() == "no rows in result set" || err.Error() == "sql: no rows in result set")
}
