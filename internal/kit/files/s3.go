package files

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

// S3Options configure any S3-compatible store. Without keys the SDK's default chain applies (instance
// roles). Objects are encrypted at rest with SSE AES256 unless DisableSSE is set.
type S3Options struct {
	Endpoint   string
	Bucket     string
	Region     string
	AccessKey  string
	SecretKey  config.Secret
	DisableSSE bool
	PathStyle  bool
}

type S3 struct {
	client  *s3.Client
	presign *s3.PresignClient
	bucket  string
	sse     bool
}

func NewS3(ctx context.Context, opts S3Options) (*S3, error) {
	if opts.Bucket == "" || opts.Region == "" {
		return nil, errors.New("files: s3 needs a bucket and a region")
	}
	loads := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(opts.Region)}
	if opts.AccessKey != "" {
		loads = append(loads, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey.Reveal(), "")))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loads...)
	if err != nil {
		return nil, fmt.Errorf("files: s3 config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if opts.Endpoint != "" {
			o.BaseEndpoint = aws.String(opts.Endpoint)
		}
		o.UsePathStyle = opts.PathStyle
	})
	return &S3{client: client, presign: s3.NewPresignClient(client), bucket: opts.Bucket, sse: !opts.DisableSSE}, nil
}

func (s *S3) Put(ctx context.Context, key string, in PutInput) error {
	if !validKey(key) {
		return errBadKey
	}
	input := &s3.PutObjectInput{
		Bucket:         aws.String(s.bucket),
		Key:            aws.String(key),
		Body:           in.Body,
		ContentLength:  aws.Int64(in.Size),
		ContentType:    aws.String(in.ContentType),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(in.SHA256[:])),
	}
	if s.sse {
		input.ServerSideEncryption = types.ServerSideEncryptionAes256
	}
	if _, err := s.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("files: s3 put: %w", err)
	}
	return nil
}

func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	if !validKey(key) {
		return nil, ObjectInfo{}, errBadKey
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, ObjectInfo{}, s3Error("get", err)
	}
	return out.Body, ObjectInfo{Key: key, Size: aws.ToInt64(out.ContentLength), ModTime: aws.ToTime(out.LastModified)}, nil
}

func (s *S3) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	if !validKey(key) {
		return ObjectInfo{}, errBadKey
	}
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return ObjectInfo{}, s3Error("stat", err)
	}
	return ObjectInfo{Key: key, Size: aws.ToInt64(out.ContentLength), ModTime: aws.ToTime(out.LastModified)}, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if !validKey(key) {
		return errBadKey
	}
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err := s3Error("delete", err); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

func (s *S3) List(ctx context.Context, prefix string, fn func(ObjectInfo) error) error {
	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(prefix)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return s3Error("list", err)
		}
		for _, o := range page.Contents {
			if err := fn(ObjectInfo{Key: aws.ToString(o.Key), Size: aws.ToInt64(o.Size), ModTime: aws.ToTime(o.LastModified)}); err != nil {
				return err
			}
		}
	}
	return nil
}

// PresignGet signs a GET that answers as an attachment with the stored type. The response cannot carry
// nosniff or a sandbox policy, so Service.PublicURL presigns only for policies that opt in.
func (s *S3) PresignGet(ctx context.Context, key string, ttl time.Duration, name, mime string) (string, error) {
	if !validKey(key) {
		return "", errBadKey
	}
	req, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket:                     aws.String(s.bucket),
		Key:                        aws.String(key),
		ResponseContentDisposition: aws.String(ContentDisposition(name)),
		ResponseContentType:        aws.String(mime),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", fmt.Errorf("files: s3 presign: %w", err)
	}
	return req.URL, nil
}

func s3Error(op string, err error) error {
	if err == nil {
		return nil
	}
	var noKey *types.NoSuchKey
	var notFound *types.NotFound
	var api smithy.APIError
	if errors.As(err, &noKey) || errors.As(err, &notFound) || (errors.As(err, &api) && api.ErrorCode() == "NoSuchKey") {
		return ErrNotFound
	}
	return fmt.Errorf("files: s3 %s: %w", op, err)
}
