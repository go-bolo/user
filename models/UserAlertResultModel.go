package user_models

import (
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/datatypes"
)

// UserAlertResultModel - Model to store user alerts results
type UserAlertResultModel struct {
	ID         uint           `gorm:"primary_key" json:"id"`
	Date       time.Time      `gorm:"column:date;type:DATE" json:"date"`
	Type       string         `gorm:"column:type;" json:"type"`
	ResultData datatypes.JSON `gorm:"column:resultData;" json:"resultData"`
	Emails     string         `gorm:"column:emails;type:TEXT;" json:"emails"`
	Title      string         `gorm:"column:title;type:TEXT" json:"title"`
	EmailHTML  string         `gorm:"column:emailHTML;type:LONGTEXT;" json:"emailHTML"`
	Error      *string        `gorm:"column:error;type:TEXT;" json:"error"`

	IsReadInWeb     bool `gorm:"column:isReadInWeb;" json:"isReadInWeb"`
	IsReadInApp     bool `gorm:"column:isReadInApp;" json:"isReadInApp"`
	IsReadInEmail   bool `gorm:"column:isReadInEmail;" json:"isReadInEmail"`
	IsSentWithEmail bool `gorm:"column:isSentWithEmail;" json:"isSentWithEmail"`
	IsSentWithPush  bool `gorm:"column:isSentWithPush;" json:"isSentWithPush"`

	EmailSendDate *time.Time `gorm:"column:emailSendDate;" json:"emailSendDate"`
	EmailReadDate *time.Time `gorm:"column:emailReadDate;" json:"emailReadDate"`
	PushSendDate  *time.Time `gorm:"column:pushSendDate;" json:"pushSendDate"`
	PushReadDate  *time.Time `gorm:"column:pushReadDate;" json:"pushReadDate"`

	TriggerId *int `gorm:"column:triggerId;type:int(11);"  json:"triggerId"`

	CreatedAt *time.Time `gorm:"column:createdAt;" sql:"DEFAULT:'current_timestamp'" json:"createdAt"`
	UpdatedAt *time.Time `gorm:"column:updatedAt;" sql:"DEFAULT:'current_timestamp'" json:"updatedAt"`
}

// TableName ...
func (r *UserAlertResultModel) TableName() string {
	return "user_alert_results"
}

func (r *UserAlertResultModel) IsRead() bool {
	if r.IsReadInWeb || r.IsReadInApp || r.IsReadInEmail {
		return true
	}

	return false
}

func (r *UserAlertResultModel) NotifyByEmail() error {
	logrus.WithFields(logrus.Fields{}).Warn("NotifyByEmail TODO send by email")

	return nil
}
