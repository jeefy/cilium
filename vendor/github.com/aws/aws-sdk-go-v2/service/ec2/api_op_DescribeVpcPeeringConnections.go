// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Describes one or more of your VPC peering connections.
func (c *Client) DescribeVpcPeeringConnections(ctx context.Context, params *DescribeVpcPeeringConnectionsInput, optFns ...func(*Options)) (*DescribeVpcPeeringConnectionsOutput, error) {
	if params == nil {
		params = &DescribeVpcPeeringConnectionsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeVpcPeeringConnections", params, optFns, addOperationDescribeVpcPeeringConnectionsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeVpcPeeringConnectionsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeVpcPeeringConnectionsInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun bool

	// One or more filters.
	//
	// * accepter-vpc-info.cidr-block - The IPv4 CIDR block of
	// the accepter VPC.
	//
	// * accepter-vpc-info.owner-id - The AWS account ID of the
	// owner of the accepter VPC.
	//
	// * accepter-vpc-info.vpc-id - The ID of the accepter
	// VPC.
	//
	// * expiration-time - The expiration date and time for the VPC peering
	// connection.
	//
	// * requester-vpc-info.cidr-block - The IPv4 CIDR block of the
	// requester's VPC.
	//
	// * requester-vpc-info.owner-id - The AWS account ID of the
	// owner of the requester VPC.
	//
	// * requester-vpc-info.vpc-id - The ID of the
	// requester VPC.
	//
	// * status-code - The status of the VPC peering connection
	// (pending-acceptance | failed | expired | provisioning | active | deleting |
	// deleted | rejected).
	//
	// * status-message - A message that provides more
	// information about the status of the VPC peering connection, if applicable.
	//
	// *
	// tag: - The key/value combination of a tag assigned to the resource. Use the tag
	// key in the filter name and the tag value as the filter value. For example, to
	// find all resources that have a tag with the key Owner and the value TeamA,
	// specify tag:Owner for the filter name and TeamA for the filter value.
	//
	// * tag-key
	// - The key of a tag assigned to the resource. Use this filter to find all
	// resources assigned a tag with a specific key, regardless of the tag value.
	//
	// *
	// vpc-peering-connection-id - The ID of the VPC peering connection.
	Filters []types.Filter

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults int32

	// The token for the next page of results.
	NextToken *string

	// One or more VPC peering connection IDs. Default: Describes all your VPC peering
	// connections.
	VpcPeeringConnectionIds []string
}

type DescribeVpcPeeringConnectionsOutput struct {

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Information about the VPC peering connections.
	VpcPeeringConnections []types.VpcPeeringConnection

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addOperationDescribeVpcPeeringConnectionsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeVpcPeeringConnections{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeVpcPeeringConnections{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddAttemptClockSkewMiddleware(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeVpcPeeringConnections(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

// DescribeVpcPeeringConnectionsAPIClient is a client that implements the
// DescribeVpcPeeringConnections operation.
type DescribeVpcPeeringConnectionsAPIClient interface {
	DescribeVpcPeeringConnections(context.Context, *DescribeVpcPeeringConnectionsInput, ...func(*Options)) (*DescribeVpcPeeringConnectionsOutput, error)
}

var _ DescribeVpcPeeringConnectionsAPIClient = (*Client)(nil)

// DescribeVpcPeeringConnectionsPaginatorOptions is the paginator options for
// DescribeVpcPeeringConnections
type DescribeVpcPeeringConnectionsPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeVpcPeeringConnectionsPaginator is a paginator for
// DescribeVpcPeeringConnections
type DescribeVpcPeeringConnectionsPaginator struct {
	options   DescribeVpcPeeringConnectionsPaginatorOptions
	client    DescribeVpcPeeringConnectionsAPIClient
	params    *DescribeVpcPeeringConnectionsInput
	nextToken *string
	firstPage bool
}

// NewDescribeVpcPeeringConnectionsPaginator returns a new
// DescribeVpcPeeringConnectionsPaginator
func NewDescribeVpcPeeringConnectionsPaginator(client DescribeVpcPeeringConnectionsAPIClient, params *DescribeVpcPeeringConnectionsInput, optFns ...func(*DescribeVpcPeeringConnectionsPaginatorOptions)) *DescribeVpcPeeringConnectionsPaginator {
	options := DescribeVpcPeeringConnectionsPaginatorOptions{}
	if params.MaxResults != 0 {
		options.Limit = params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	if params == nil {
		params = &DescribeVpcPeeringConnectionsInput{}
	}

	return &DescribeVpcPeeringConnectionsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeVpcPeeringConnectionsPaginator) HasMorePages() bool {
	return p.firstPage || p.nextToken != nil
}

// NextPage retrieves the next DescribeVpcPeeringConnections page.
func (p *DescribeVpcPeeringConnectionsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeVpcPeeringConnectionsOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	params.MaxResults = p.options.Limit

	result, err := p.client.DescribeVpcPeeringConnections(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken && prevToken != nil && p.nextToken != nil && *prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opDescribeVpcPeeringConnections(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DescribeVpcPeeringConnections",
	}
}
