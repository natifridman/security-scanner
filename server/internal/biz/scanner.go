package biz

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
)

// ScannerRepo is a Scanner model.
type Scanner struct {
	Repository string
}

// ScannerRepo is a Scanner repo.
type ScannerRepo interface {
	Save(context.Context, *Scanner) (*Scanner, error)
	Update(context.Context, *Scanner) (*Scanner, error)
	FindByID(context.Context, int64) (*Scanner, error)
	ListByHello(context.Context, string) ([]*Scanner, error)
	ListAll(context.Context) ([]*Scanner, error)
}

// ScannerUsecase is a Scanner usecase.
type ScannerUsecase struct {
	repo ScannerRepo
	log  *log.Helper
}

// NewScannerUsecase new a Scanner usecase.
func NewScannerUsecase(repo ScannerRepo, logger log.Logger) *ScannerUsecase {
	return &ScannerUsecase{repo: repo, log: log.NewHelper(logger)}
}

// CreateScanner creates a Scanner, and returns the new Scanner.
func (uc *ScannerUsecase) CreateScanner(ctx context.Context, s *Scanner) (*Scanner, error) {
	uc.log.WithContext(ctx).Infof("CreateScanner: %v", s.Repository)
	return uc.repo.Save(ctx, s)
}
