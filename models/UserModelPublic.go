package user_models

import (
	"strconv"
	"time"
)

type UserModelPublic struct {
	ID uint64 `gorm:"primary_key;column:id;" json:"id" filter:"param:id;type:number"`

	Username string `gorm:"unique;column:username;" json:"username" filter:"param:username;type:string"`

	DisplayName string `gorm:"column:displayName;" json:"displayName" filter:"param:displayName;type:string"`

	Language string `gorm:"column:language;" json:"language" filter:"param:language;type:string"`

	CreatedAt time.Time `gorm:"column:createdAt;" json:"createdAt" filter:"param:createdAt;type:date"`
	UpdatedAt time.Time `gorm:"column:updatedAt;" json:"updatedAt" filter:"param:updatedAt;type:date"`
}

// TableName get sql table name
func (m *UserModelPublic) TableName() string {
	return "users"
}

func (r *UserModelPublic) GetID() string {
	return strconv.FormatUint(r.ID, 10)
}

func NewUserModelPublicFromUserModel(userRecord *UserModel) *UserModelPublic {
	return &UserModelPublic{
		ID:          userRecord.ID,
		Username:    userRecord.Username,
		DisplayName: userRecord.DisplayName,
		Language:    userRecord.GetLanguage(),
		CreatedAt:   userRecord.CreatedAt,
		UpdatedAt:   userRecord.UpdatedAt,
	}
}
