<?xml version="1.0" encoding="iso-8859-2"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<!--
     Extract facet/focus list from classification.xml
     
     Usage:  xsltproc extract-facets.xsl classification.xml
-->
<xsl:output method="text"/>

<xsl:template match="text()|@*"/>

<xsl:key name="tags" match="tag" use="@value"/>

<xsl:template match="classification/global/facet">
    <xsl:param name="name" select="@name"/>
    <xsl:value-of select="$name"/>
    <xsl:text>
</xsl:text>
    <xsl:for-each select="//classification/block/tag[@name=$name][generate-id()=generate-id(key('tags',@value)[1])]">
        <xsl:sort select="@value"/>
        <xsl:text>    </xsl:text><xsl:value-of select="@value"/>
        <xsl:text>
</xsl:text>
    </xsl:for-each>
</xsl:template>

</xsl:stylesheet>
