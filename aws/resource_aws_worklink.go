package aws

import (
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/worklink"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceAwsWorkLink() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsWorkLinkCreate,
		Read:   resourceAwsWorkLinkRead,
		Update: resourceAwsWorkLinkUpdate,
		Delete: resourceAwsWorkLinkDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateWorklinkFleetName,
			},
			"display_name": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringLenBetween(0, 100),
			},
			"audit_stream_arn": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validateArn,
			},
			"network": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"vpc_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"security_group_ids": {
							Type:     schema.TypeSet,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      schema.HashString,
						},
						"subnet_ids": {
							Type:     schema.TypeSet,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      schema.HashString,
						},
					},
				},
			},
			"device_ca_certificate": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"identity_provider": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"saml_metadata": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringLenBetween(1, 204800),
						},
						"service_provider_saml_metadata": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"company_code": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"last_updated_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"optimize_for_end_user_location": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
		},
	}
}

func resourceAwsWorkLinkCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).worklinkconn

	input := &worklink.CreateFleetInput{
		FleetName:                  aws.String(d.Get("name").(string)),
		OptimizeForEndUserLocation: aws.Bool(d.Get("optimize_for_end_user_location").(bool)),
	}

	if v, ok := d.GetOk("display_name"); ok {
		input.DisplayName = aws.String(v.(string))
	}

	resp, err := conn.CreateFleet(input)
	if err != nil {
		return fmt.Errorf("Error creating Worklink Fleet: %s", err)
	}

	d.SetId(aws.StringValue(resp.FleetArn))
	return resourceAwsWorkLinkUpdate(d, meta)
}

func resourceAwsWorkLinkRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).worklinkconn

	resp, err := conn.DescribeFleetMetadata(&worklink.DescribeFleetMetadataInput{
		FleetArn: aws.String(d.Id()),
	})
	if err != nil {
		if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
			log.Printf("[WARN] Worklink Fleet (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error describe worklink fleet: %s", err)
	}

	d.Set("arn", d.Id())
	d.Set("name", aws.StringValue(resp.FleetName))
	d.Set("display_name", aws.StringValue(resp.DisplayName))
	d.Set("optimize_for_end_user_location", aws.BoolValue(resp.OptimizeForEndUserLocation))
	d.Set("company_code", aws.StringValue(resp.CompanyCode))
	d.Set("created_time", resp.CreatedTime.Format(time.RFC3339))
	if resp.LastUpdatedTime != nil {
		d.Set("last_updated_time", resp.LastUpdatedTime.Format(time.RFC3339))
	}
	auditStreamConfigurationResp, err := conn.DescribeAuditStreamConfiguration(&worklink.DescribeAuditStreamConfigurationInput{
		FleetArn: aws.String(d.Id()),
	})
	if err != nil {
		return fmt.Errorf("Error describe worklink audit stream configuration: %s", err)
	}
	d.Set("audit_stream_arn", auditStreamConfigurationResp.AuditStreamArn)

	companyNetworkConfigurationResp, err := conn.DescribeCompanyNetworkConfiguration(&worklink.DescribeCompanyNetworkConfigurationInput{
		FleetArn: aws.String(d.Id()),
	})
	if err != nil {
		return fmt.Errorf("Error describe worklink company network configuration: %s", err)
	}
	d.Set("network", flattenWorkLinkNetworkConfigResponse(companyNetworkConfigurationResp))

	identityProviderConfigurationResp, err := conn.DescribeIdentityProviderConfiguration(&worklink.DescribeIdentityProviderConfigurationInput{
		FleetArn: aws.String(d.Id()),
	})
	if err != nil {
		return fmt.Errorf("Error describe worklink company network configuration: %s", err)
	}
	d.Set("identity_provider", flattenWorkLinkIdentityProviderConfigResponse(identityProviderConfigurationResp))

	devicePolicyConfigurationResp, err := conn.DescribeDevicePolicyConfiguration(&worklink.DescribeDevicePolicyConfigurationInput{
		FleetArn: aws.String(d.Id()),
	})
	if err != nil {
		return fmt.Errorf("Error describe worklink device policy configuration: %s", err)
	}
	d.Set("device_ca_certificate", devicePolicyConfigurationResp.DeviceCaCertificate)

	return nil
}

func resourceAwsWorkLinkUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).worklinkconn

	input := &worklink.UpdateFleetMetadataInput{
		FleetArn:                   aws.String(d.Id()),
		OptimizeForEndUserLocation: aws.Bool(d.Get("optimize_for_end_user_location").(bool)),
	}

	if v, ok := d.GetOk("display_name"); ok {
		input.DisplayName = aws.String(v.(string))
	}

	if d.HasChange("display_name") || d.HasChange("optimize_for_end_user_location") {
		_, err := conn.UpdateFleetMetadata(input)
		if err != nil {
			if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
				log.Printf("[WARN] Worklink Fleet (%s) not found, removing from state", d.Id())
				d.SetId("")
				return nil
			}
			return fmt.Errorf("Error updating worklink fleet: %s", err)
		}
	}

	if d.HasChange("audit_stream_arn") {
		if err := updateAuditStreamConfiguration(conn, d); err != nil {
			return err
		}
	}

	if d.HasChange("network") {
		if err := updateCompanyNetworkConfiguration(conn, d); err != nil {
			return err
		}
	}

	if d.HasChange("device_ca_certificate") {
		if err := updateDevicePolicyConfiguration(conn, d); err != nil {
			return err
		}
	}

	if d.HasChange("identity_provider") || d.IsNewResource() {
		if err := updateIdentityProviderConfiguration(conn, d); err != nil {
			return err
		}
	}

	return resourceAwsWorkLinkRead(d, meta)
}

func resourceAwsWorkLinkDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).worklinkconn

	input := &worklink.DeleteFleetInput{
		FleetArn: aws.String(d.Id()),
	}

	if _, err := conn.DeleteFleet(input); err != nil {
		if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
			return nil
		}
		return fmt.Errorf("Error deleting Worklink Fleet resource share %s: %s", d.Id(), err)
	}

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"DELETING"},
		Target:     []string{"DELETED"},
		Refresh:    worklinkFleetStateRefresh(conn, d.Id()),
		Timeout:    15 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	_, err := stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf(
			"Error waiting for Worklink Fleet (%s) to become deleted: %s",
			d.Id(), err)
	}

	return nil
}

func worklinkFleetStateRefresh(conn *worklink.WorkLink, arn string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		emptyResp := &worklink.DescribeFleetMetadataOutput{}

		resp, err := conn.DescribeFleetMetadata(&worklink.DescribeFleetMetadataInput{
			FleetArn: aws.String(arn),
		})
		if err != nil {
			if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
				return emptyResp, "DELETED", nil
			}
		}

		return resp, *resp.FleetStatus, nil
	}
}

func updateAuditStreamConfiguration(conn *worklink.WorkLink, d *schema.ResourceData) error {
	if _, err := conn.UpdateAuditStreamConfiguration(&worklink.UpdateAuditStreamConfigurationInput{
		AuditStreamArn: aws.String(d.Get("audit_stream_arn").(string)),
		FleetArn:       aws.String(d.Id()),
	}); err != nil {
		if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
			log.Printf("[WARN] Worklink Fleet (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error Updating Worklink Audit Stream Configuration: %s", err)
	}

	return nil
}

func updateCompanyNetworkConfiguration(conn *worklink.WorkLink, d *schema.ResourceData) error {
	if v, ok := d.GetOk("network"); ok && len(v.([]interface{})) > 0 {
		config := v.([]interface{})[0].(map[string]interface{})

		input := &worklink.UpdateCompanyNetworkConfigurationInput{
			FleetArn:         aws.String(d.Id()),
			SecurityGroupIds: expandStringSet(config["security_group_ids"].(*schema.Set)),
			SubnetIds:        expandStringSet(config["subnet_ids"].(*schema.Set)),
			VpcId:            aws.String(config["vpc_id"].(string)),
		}
		if _, err := conn.UpdateCompanyNetworkConfiguration(input); err != nil {
			if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
				log.Printf("[WARN] Worklink Fleet (%s) not found, removing from state", d.Id())
				d.SetId("")
				return nil
			}
			return fmt.Errorf("Error Updating Worklink Network Configuration: %s", err)
		}
	}
	return nil
}

func updateDevicePolicyConfiguration(conn *worklink.WorkLink, d *schema.ResourceData) error {
	if _, err := conn.UpdateDevicePolicyConfiguration(&worklink.UpdateDevicePolicyConfigurationInput{
		DeviceCaCertificate: aws.String(d.Get("device_ca_certificate").(string)),
		FleetArn:            aws.String(d.Id()),
	}); err != nil {
		if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
			log.Printf("[WARN] Worklink Fleet (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error Updating Worklink Device Policy Configuration: %s", err)
	}
	return nil
}

func updateIdentityProviderConfiguration(conn *worklink.WorkLink, d *schema.ResourceData) error {
	if v, ok := d.GetOk("identity_provider"); ok && len(v.([]interface{})) > 0 {
		config := v.([]interface{})[0].(map[string]interface{})

		input := &worklink.UpdateIdentityProviderConfigurationInput{
			FleetArn:                     aws.String(d.Id()),
			IdentityProviderSamlMetadata: aws.String(config["saml_metadata"].(string)),
			IdentityProviderType:         aws.String(config["type"].(string)),
		}
		if _, err := conn.UpdateIdentityProviderConfiguration(input); err != nil {
			if isAWSErr(err, worklink.ErrCodeResourceNotFoundException, "") {
				log.Printf("[WARN] Worklink Fleet (%s) not found, removing from state", d.Id())
				d.SetId("")
				return nil
			}
			return fmt.Errorf("Error Updating Identity Provider Configuration: %s", err)
		}
	}

	return nil
}
