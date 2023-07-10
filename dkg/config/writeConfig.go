package config

import (
	"dkg/crypto/binaryquadraticform"
	"fmt"

	"github.com/spf13/viper"
)

// write new m_k and r_k
func WriteSetup(m_k *binaryquadraticform.BQuadraticForm, r_k *binaryquadraticform.BQuadraticForm, proof *binaryquadraticform.BQuadraticForm) {
	// set config file
	outputViper := viper.New()
	outputViper.SetConfigFile("config/config.yml")

	// read config and keep origin settings
	if err := outputViper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("===>[ERROR from WriteSetup]Read config file failed:%s", err))
	}

	outputViper.Set("m_k_a", m_k.GetA())
	outputViper.Set("m_k_b", m_k.GetB())
	outputViper.Set("m_k_c", m_k.GetC())
	outputViper.Set("r_k_a", r_k.GetA())
	outputViper.Set("r_k_b", r_k.GetB())
	outputViper.Set("r_k_c", r_k.GetC())
	outputViper.Set("p_a", proof.GetA())
	outputViper.Set("p_b", proof.GetB())
	outputViper.Set("p_c", proof.GetC())

	// write new settings
	if err := outputViper.WriteConfig(); err != nil {
		panic(fmt.Errorf("===>[ERROR from WriteSetup]Write config file failed:%s", err))
	}

	fmt.Println("===>[WriteSetup]Write output success")
}
