package data

import (
	"context"

	"server/internal/biz"

	"github.com/go-kratos/kratos/v2/log"
)

type scannerRepo struct {
	data *Data
	log  *log.Helper
}

// NewScannerRepo .
func NewScannerRepo(data *Data, logger log.Logger) biz.ScannerRepo {
	return &scannerRepo{
		data: data,
		log:  log.NewHelper(logger),
	}
}

func (r *scannerRepo) Save(ctx context.Context, g *biz.Scanner) (*biz.Scanner, error) {
	return g, nil
}

func (r *scannerRepo) Update(ctx context.Context, g *biz.Scanner) (*biz.Scanner, error) {
	return g, nil
}

func (r *scannerRepo) FindByID(context.Context, int64) (*biz.Scanner, error) {
	return nil, nil
}

func (r *scannerRepo) ListByHello(context.Context, string) ([]*biz.Scanner, error) {
	return nil, nil
}

func (r *scannerRepo) ListAll(context.Context) ([]*biz.Scanner, error) {
	return nil, nil
}
