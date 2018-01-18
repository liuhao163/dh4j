package com.ericliu.encrypt.dh4j;

public enum HQDHSymmetricalAlgorithm
{
    DES("DES"), DESede("DESede");
    private String name;

    private HQDHSymmetricalAlgorithm(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return this.name;
    }
}