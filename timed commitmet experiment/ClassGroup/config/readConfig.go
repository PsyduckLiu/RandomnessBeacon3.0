package config

import (
	"fmt"
	"math/big"

	"github.com/spf13/viper"
)

// get class group parameter from config file
func GetGroupParameter() (*big.Int, *big.Int, *big.Int) {
	// set config file
	configViper := viper.New()
	configViper.SetConfigFile("config/config.yml")

	if err := configViper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("===>[ERROR from GetGroupParameter]Read config file failed:%s", err))
	}

	a, _ := big.NewInt(0).SetString(configViper.GetString("a"), 10)
	b, _ := big.NewInt(0).SetString(configViper.GetString("b"), 10)
	c, _ := big.NewInt(0).SetString(configViper.GetString("c"), 10)

	return a, b, c
}

// get time parameter from config file
func GetTimeParameter() int {
	// set config file
	configViper := viper.New()
	configViper.SetConfigFile("config/config.yml")

	if err := configViper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("===>[ERROR from GetGroupParameter]Read config file failed:%s", err))
	}

	return configViper.GetInt("t")
}

// get public group parameter from config file
func GetPublicGroupParameter() (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {
	// set config file
	configViper := viper.New()
	configViper.SetConfigFile("config/config.yml")

	if err := configViper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("===>[ERROR from GetGroupParameter]Read config file failed:%s", err))
	}

	m_k_a, _ := big.NewInt(0).SetString(configViper.GetString("m_k_a"), 10)
	m_k_b, _ := big.NewInt(0).SetString(configViper.GetString("m_k_b"), 10)
	m_k_c, _ := big.NewInt(0).SetString(configViper.GetString("m_k_c"), 10)
	r_k_a, _ := big.NewInt(0).SetString(configViper.GetString("r_k_a"), 10)
	r_k_b, _ := big.NewInt(0).SetString(configViper.GetString("r_k_b"), 10)
	r_k_c, _ := big.NewInt(0).SetString(configViper.GetString("r_k_c"), 10)

	return m_k_a, m_k_b, m_k_c, r_k_a, r_k_b, r_k_c
}

// get public parameter proof from config file
func GetPublicParameterProof() (*big.Int, *big.Int, *big.Int) {
	// set config file
	configViper := viper.New()
	configViper.SetConfigFile("config/config.yml")

	if err := configViper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("===>[ERROR from GetGroupParameter]Read config file failed:%s", err))
	}

	p_a, _ := big.NewInt(0).SetString(configViper.GetString("p_a"), 10)
	p_b, _ := big.NewInt(0).SetString(configViper.GetString("p_b"), 10)
	p_c, _ := big.NewInt(0).SetString(configViper.GetString("p_c"), 10)

	return p_a, p_b, p_c
}
