package service

import (
	"context"

	"encoding/json"
	pb "server/api/server"
	"server/internal/biz"
)

type ScannerService struct {
	pb.UnimplementedScannerServer

	uc *biz.ScannerUsecase
}

func NewScannerService(uc *biz.ScannerUsecase) *ScannerService {
	return &ScannerService{uc: uc}
}

func (s *ScannerService) Scan(ctx context.Context, req *pb.ScanRequest) (*pb.ScanReply, error) {
	g, err := s.uc.CreateScanner(ctx, &biz.Scanner{Repository: req.Name})

	if err != nil {
		return nil, err
	}

	// Convert struct to JSON
	jsonData, err := json.Marshal(g.ScannedRepos)
	if err != nil {
		return nil, err
	}
	return &pb.ScanReply{Message: string(jsonData)}, nil
}
